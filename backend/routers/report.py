# generez raportul ca text simplu: frontendul trimite inregistrarea scanarii
# din localStorage si primeste inapoi un rezumat .txt descarcabil
# am doua aranjamente: unul pentru scanari Dockerfile/Compose, unul pentru imagini (Dive)
from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

router = APIRouter()


class ReportRequest(BaseModel):
    # copia inregistrarii scanarii din localStorage
    id: str = ""
    job_kind: str = "dockerfile_compose"   # dockerfile_compose | image | combined
    filename: str = ""
    label: str = ""
    job_status: str = "completed"
    created_at: str = ""
    verdict: str = "PENDING"
    total_findings: int = 0
    hadolint_issues: int = 0
    trivy_issues: int = 0
    package_issues: int = 0
    cis_issues: int = 0
    summary: dict | None = None
    files: list = Field(default_factory=list)
    events: list = Field(default_factory=list)
    image_input: dict | None = None         # name + kind + ref for combined scans


# ordonez categoriile in raport de la cele mai actionabile la cele mai putin
_CATEGORY_ORDER = (
    "secrets", "critical_misconfig", "cve_base_image",
    "cve_packages", "best_practices", "code_quality",
)


def _detect_cve_source(events: list) -> tuple[str, bool]:
    # vad ce sursa de CVE s-a folosit (OSV/NVD) si daca s-a trecut pe rezerva
    # scanerul de pachete marcheaza evenimentele corespunzator
    src = "—"
    fallback = False
    for ev in events:
        if ev.get("tool") == "package" and ev.get("source") in ("osv", "nvd") and src == "—":
            src = ev["source"].upper()
        if ev.get("source") == "fallback":
            fallback = True
    return src, fallback


def _image_metrics_block(summary: dict, dash: str) -> list[str]:
    # blocul cu metrici Dive: dimensiune, straturi, eficienta, octeti irositi,
    # fisierele cu cel mai mult spatiu pierdut si categoriile de imagine
    # lista goala daca scanarea nu are image_summary (adica Dive n-a rulat)
    img = summary.get("image_summary") or {}
    if not img:
        return []

    eff = (img.get("efficiency", 1) or 1) * 100
    L = [
        dash, "  POST-BUILD IMAGE ANALYSIS (Dive)", dash,
        f"  Total size:    {img.get('size_bytes', 0) / 1024 / 1024:.1f} MB",
        f"  Layer count:   {img.get('layer_count', 0)}",
        f"  Efficiency:    {eff:.1f}%",
        f"  Wasted bytes:  {img.get('wasted_bytes', 0) / 1024 / 1024:.1f} MB",
    ]

    top = img.get("top_waste_files") or []
    if top:
        L += ["", "  Top wasted-space files:"]
        for w in top:
            size_mb = (w.get("size", 0) or 0) / 1024 / 1024
            L.append(f"    {w.get('path','?')}  —  {size_mb:.1f} MB × {w.get('count',1)} layer(s)")

    return L


def _render_dockerfile_report(s: ReportRequest) -> str:
    events  = s.events or []
    summary = s.summary or {}
    files   = s.files or []
    grand   = s.total_findings or (
        s.hadolint_issues + s.trivy_issues + s.package_issues + s.cis_issues
    )
    cve_src, fallback = _detect_cve_source(events)
    is_combined = (s.job_kind == "combined") and (s.image_input or summary.get("image_summary"))

    sep, dash = "=" * 72, "-" * 72
    title = ("  DOCKER HARDENING HUB — COMBINED SCAN REPORT"
             if is_combined else "  DOCKER HARDENING HUB — SCAN REPORT")
    L = [
        sep, title, sep,
        f"  Scan ID:       {s.id or '—'}",
        f"  Timestamp:     {s.created_at or '?'} UTC",
        f"  Status:        {s.job_status}",
        f"  Label:         {s.filename or s.label}",
        f"  Files:         {len(files) or 1}",
        f"  CVE source:    {cve_src}" + (" (NVD fallback — OSV unreachable)" if fallback else ""),
    ]
    if is_combined and s.image_input:
        img_kind = s.image_input.get("kind", "?")
        img_name = s.image_input.get("name") or s.image_input.get("ref") or "?"
        L.append(f"  Image input:   {img_name}  ({img_kind})")
    L.append("")

    L += [
        dash, "  VERDICT", dash,
        f"  Overall:       {s.verdict}",
        f"  Findings:      {grand}",
    ]

    categories = summary.get("categories") or {}
    if categories:
        L += ["", "  Category breakdown:"]
        for cat_id, cat in categories.items():
            metric = cat.get("metric", "")
            count  = cat.get("count")
            tail   = metric if metric else (f"{count} finding(s)" if count is not None else "")
            L.append(f"    {cat.get('label', cat_id):<22} "
                     f"{cat.get('verdict','PASS'):<10} {tail}")

    L += [
        "",
        dash, "  TOTALS BY SCANNER", dash,
        f"  hadolint        {s.hadolint_issues}",
        f"  trivy           {s.trivy_issues}",
        f"  package CVEs    {s.package_issues}  (source: {cve_src})",
        f"  cis             {s.cis_issues}",
        f"  TOTAL           {grand}",
    ]

    # blocul cu metrici Dive apare doar la scanarile combinate
    if is_combined:
        L += [""]
        L += _image_metrics_block(summary, dash)

    L += ["", sep, "  DETAILED FINDINGS", sep]

    # grupez fiecare problema dupa fisierul de sursa (sau numele imaginii)
    file_kinds = {f.get("name", "?"): f.get("kind", "?") for f in files if isinstance(f, dict)}
    # la scanarile combinate leg si numele imaginii de tipul ei, ca rezultatele
    # sa apara marcate corect cu "tarball" / "ref" in loc de "?"
    if is_combined and s.image_input:
        img_name = s.image_input.get("name") or s.image_input.get("ref")
        if img_name:
            file_kinds[img_name] = s.image_input.get("kind", "image")

    by_file: dict[str, list] = {}
    for ev in events:
        if ev.get("type") == "issue":
            by_file.setdefault(ev.get("file", "?"), []).append(ev)

    if not by_file:
        L += ["", "  No findings recorded."]
    else:
        for fname, issues in by_file.items():
            kind = file_kinds.get(fname, "?")
            L += [
                "", "",
                "╔" + "═" * 70 + "╗",
                f"║  FILE: {fname}".ljust(71) + "║",
                f"║  Type: {kind}    Findings: {len(issues)}".ljust(71) + "║",
                "╚" + "═" * 70 + "╝",
                "",
            ]
            for iss in issues:
                L.append(
                    f"    [{(iss.get('tool') or '?').upper():<10}] "
                    f"{(iss.get('level') or '').upper():<8} {iss.get('message','')}"
                )

    L += ["", sep, "  END OF REPORT", sep]
    return "\n".join(L)


def _render_image_report(s: ReportRequest) -> str:
    summary = s.summary or {}
    cats    = summary.get("categories") or {}
    events  = s.events or []

    sep, dash = "=" * 72, "-" * 72
    L = [
        sep, "  DOCKER HARDENING HUB — IMAGE ANALYSIS REPORT", sep,
        f"  Scan ID:       {s.id or '—'}",
        f"  Timestamp:     {s.created_at or '?'} UTC",
        f"  Status:        {s.job_status}",
        f"  Image:         {s.filename or s.label}",
        "",
        dash, "  VERDICT", dash,
        f"  Overall:       {s.verdict}",
        "",
    ]
    L += _image_metrics_block(summary, dash)

    L += ["", dash, "  CATEGORY BREAKDOWN", dash]
    for cat_id, cat in cats.items():
        L.append(f"  {cat.get('label', cat_id):<22} "
                 f"{cat.get('verdict','?'):<10} {cat.get('metric','')}")

    L += ["", dash, "  EVENT LOG", dash]
    for ev in events:
        if ev.get("type") in ("issue", "info", "error", "warning"):
            L.append(
                f"    [{(ev.get('tool') or '?').upper():<8}] "
                f"{(ev.get('level') or ev.get('type') or '').upper():<8} {ev.get('message','')}"
            )

    L += ["", sep, "  END OF REPORT", sep]
    return "\n".join(L)


@router.post("/report")
async def download_report(scan: ReportRequest):
    if not scan.id and not scan.filename:
        raise HTTPException(400, "Empty scan payload")

    body = (_render_image_report(scan) if scan.job_kind == "image"
            else _render_dockerfile_report(scan))
    safe_id = (scan.id or "scan").replace("/", "_")
    return PlainTextResponse(
        body,
        headers={
            "Content-Disposition": f'attachment; filename="dhh-report-{safe_id}.txt"',
            "Content-Type":        "text/plain; charset=utf-8",
        },
    )
