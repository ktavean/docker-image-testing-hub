# punctare pe categorii, am doua functii:
#   compute_score       pentru Dockerfile/Compose, sase categorii
#   compute_image_score pentru imagine (Dive), patru categorii
# amandoua dau acelasi tip de verdict (APPROVED/WARNING/POLICY_REJECTED)
# plus detalierea pe categorii; verdictul global e categoria cea mai rea

# Modul Dockerfile / Compose

# (id, eticheta, descriere). Ordinea e cea in care apar in interfata.
_CATEGORIES = [
    ("secrets",            "Secrets",              "Hardcoded credentials in Dockerfile/Compose"),
    ("critical_misconfig", "Critical Misconfig",   "Privileged containers, socket mounts, escape vectors"),
    ("cve_base_image",     "CVEs — Base Image",    "Known CVEs in the FROM image"),
    ("cve_packages",       "CVEs — Packages",      "Known CVEs in installed packages"),
    ("best_practices",     "Best Practices",       "Hadolint findings, CIS recommendations"),
    ("code_quality",       "Code Quality",         "Style and informational issues"),
]

# Instrumente care merg mereu intr-o singura categorie, indiferent de severitate.
_DIRECT_TOOL_CATEGORY = {
    "trivy-secret": "secrets",
    "trivy-image":  "cve_base_image",
    "package":      "cve_packages",
    "osv":          "cve_packages",
    "nvd":          "cve_packages",
}

# Reguli CIS ridicate la "critical_misconfig" chiar cand severitatea lor
# nu e literalmente "critical": acestea sunt vectorii reali de evadare
# (privileged:true, montarea socketului Docker, curl|bash etc.).
_CRITICAL_CIS_RULES = ("CIS-4.11", "CIS-5.4", "CIS-5.5", "CIS-5.32")

# Severitati care ridica o categorie la WARNING. CRITICAL se trateaza
# separat, fiindca are mereu intaietate.
_WARNING_LEVELS = frozenset({"high", "medium", "warning", "error"})

# Categorii care pot afisa probleme — inclusiv CRITICAL — dar care NU
# trebuie sa forteze singure POLICY_REJECTED. Un CVE critic in imaginea
# de baza sau intr-un pachet de distributie e real si ramane afisat ca
# CRITICAL in detalierea categoriei, dar nu blocheaza construirea:
#   - de cele mai multe ori nu e vina autorului Dockerfile-ului (cel care
#     intretine imaginea de baza inca nu a livrat un patch),
#   - versiunea reparata poate nici sa nu existe in momentul scanarii,
#   - blocarea pe el ar face verdictul sa oscileze de la o zi la alta, pe
#     masura ce fluxul de CVE se actualizeaza, fara nicio modificare in
#     Dockerfile.
# Blocarea e rezervata pentru ce controleaza autorul si ce semnaleaza
# intentie sau neglijenta: secrete hardcodate si configurari de tip vector
# de evadare. Ca o categorie sa blocheze din nou, scoate-o de aici.
_NON_GATING_CATEGORIES = frozenset({"cve_base_image", "cve_packages"})


def _categorize(event: dict) -> str | None:
    # bag un eveniment intr-o categorie; None inseamna ca-l sar
    if event.get("type") != "issue":
        return None

    tool  = event.get("tool", "")
    level = (event.get("level") or "").lower()
    code  = event.get("code", "") or ""

    if tool in _DIRECT_TOOL_CATEGORY:
        return _DIRECT_TOOL_CATEGORY[tool]

    if tool in ("cis", "compose-advisor"):
        if level == "critical" or any(r in code for r in _CRITICAL_CIS_RULES):
            return "critical_misconfig"
        return "best_practices"

    if tool == "trivy":
        return "critical_misconfig" if level == "critical" else "best_practices"

    if tool == "hadolint":
        return "best_practices" if level in ("error", "warning") else "code_quality"

    # Instrument necunoscut: ghicim dupa severitate.
    if level == "critical":         return "critical_misconfig"
    if level in ("info", "style"):  return "code_quality"
    return "best_practices"


def _verdict_from_levels(levels) -> str:
    # verdictul unei categorii, scos din severitatile care au cazut pe ea
    sevs = {s.lower() for s in levels}
    if not sevs:               return "PASS"
    if "critical" in sevs:     return "CRITICAL"
    if sevs & _WARNING_LEVELS: return "WARNING"
    return "INFO"


def compute_score(events: list[dict]) -> dict:
    tally: dict[str, dict] = {cat_id: {"count": 0, "severities": {}}
                              for cat_id, _, _ in _CATEGORIES}
    total = 0

    for ev in events:
        cat = _categorize(ev)
        if cat is None:
            continue
        level = (ev.get("level") or "info").lower()
        # Regulile CIS de tip vector de evadare (curl|bash, privileged,
        # montare socket, capabilitati periculoase) blocheaza construirea.
        # _categorize le pune deja in critical_misconfig, dar nu toti
        # analizoarele le marcheaza ca "critical" — de pilda cis_advisor
        # emite CIS-4.11 ca "high". Fortam severitatea aici, ca verdictul
        # categoriei sa reflecte cu adevarat "acesta e un vector de evadare".
        code = ev.get("code", "") or ""
        if ev.get("tool") in ("cis", "compose-advisor") and \
           any(r in code for r in _CRITICAL_CIS_RULES):
            level = "critical"
        tally[cat]["count"] += 1
        tally[cat]["severities"][level] = tally[cat]["severities"].get(level, 0) + 1
        total += 1

    categories_out = {
        cat_id: {
            "label":       label,
            "description": desc,
            "count":       tally[cat_id]["count"],
            "severities":  tally[cat_id]["severities"],
            "verdict":     _verdict_from_levels(tally[cat_id]["severities"]),
        }
        for cat_id, label, desc in _CATEGORIES
    }

    # Verdict global: cel mai sever per categorie, cu o exceptie —
    # categoriile de CVE avertizeaza dar nu blocheaza (vezi
    # _NON_GATING_CATEGORIES). Verdictul propriu al categoriei in
    # detaliere ramane onest; asta afecteaza doar ce poate impinge
    # rezultatul global spre POLICY_REJECTED.
    gating_verdicts = set()
    for cat_id, c in categories_out.items():
        v = c["verdict"]
        if v == "CRITICAL" and cat_id in _NON_GATING_CATEGORIES:
            v = "WARNING"   # CVE critic -> avertizeaza, nu respinge
        gating_verdicts.add(v)
    if   "CRITICAL" in gating_verdicts: overall = "POLICY_REJECTED"
    elif "WARNING"  in gating_verdicts: overall = "WARNING"
    else:                               overall = "APPROVED"

    return {"verdict": overall, "total_findings": total, "categories": categories_out}


# Modul imagine (Dive)

_IMAGE_CATEGORIES = [
    ("image_size",       "Image Size",       "Total uncompressed image size"),
    ("layer_efficiency", "Layer Efficiency", "How well layers reuse data (1.0 = no duplication)"),
    ("wasted_space",     "Wasted Space",     "Bytes duplicated or replaced across layers"),
    ("cve_findings",     "CVEs (built image)", "High/critical CVEs reported by Trivy"),
]

# De tinut sincronizat cu dive_scanner._classify, ca sa se potriveasca
# culorile din consola live cu verdictul.
_SIZE_WARN_BYTES   = 1024 * 1024 * 1024
_SIZE_INFO_BYTES   = 500  * 1024 * 1024
_EFFICIENCY_WARN   = 0.95
_EFFICIENCY_CRIT   = 0.85
_WASTED_WARN_BYTES = 50  * 1024 * 1024
_WASTED_CRIT_BYTES = 200 * 1024 * 1024

# Praguri CVE — aceeasi idee ca punctarea in mod Dockerfile, dar aplicata
# rezultatelor de dupa construire. CVE-urile critice sunt deblocate (coboara
# la WARNING), pentru consecventa cu _NON_GATING_CATEGORIES; operatorul
# trebuie sa le vada si sa decida.
_CVE_WARN_COUNT = 1     # orice CVE high/critical declanseaza WARNING


def _image_verdict_size(b: int) -> str:
    if b > _SIZE_WARN_BYTES: return "WARNING"
    if b > _SIZE_INFO_BYTES: return "INFO"
    return "PASS"


def _image_verdict_efficiency(e: float) -> str:
    if e < _EFFICIENCY_CRIT: return "CRITICAL"
    if e < _EFFICIENCY_WARN: return "WARNING"
    return "PASS"


def _image_verdict_wasted(b: int) -> str:
    if b > _WASTED_CRIT_BYTES: return "CRITICAL"
    if b > _WASTED_WARN_BYTES: return "WARNING"
    if b > 0:                  return "INFO"
    return "PASS"


def compute_image_score(events: list[dict]) -> dict:
    # iau sumarul din evenimentul done al lui dive plus CVE-urile trivy-image
    # si le aduc la aceeasi forma ca la compute_score, ca frontendul sa le
    # afiseze la fel si pentru dockerfile si pentru imagine
    summary = next(
        (ev["summary"] for ev in events
         if ev.get("tool") == "dive" and ev.get("type") == "done" and ev.get("summary")),
        {},
    )

    size_bytes   = int(summary.get("size_bytes", 0)   or 0)
    wasted_bytes = int(summary.get("wasted_bytes", 0) or 0)
    efficiency   = float(summary.get("efficiency", 1.0) or 1.0)
    layer_count  = int(summary.get("layer_count", 0)  or 0)
    top_waste    = summary.get("top_waste_files", []) or []

    # Numaram problemele trivy-image. Campul 'level' de pe probleme e
    # severitatea Trivy in litere mici (critical/high/medium/low).
    cve_issues = [ev for ev in events
                  if ev.get("tool") == "trivy-image" and ev.get("type") == "issue"]
    cve_critical = sum(1 for ev in cve_issues if ev.get("level") == "critical")
    cve_high     = sum(1 for ev in cve_issues if ev.get("level") == "high")
    cve_total    = len(cve_issues)

    # A rulat trivy efectiv? Daca nu exista eveniment 'done' de la
    # trivy-image, tratam categoria ca N/A in loc de PASS, ca interfata
    # sa poata distinge intre "fara CVE" si "scanerul nu a rulat".
    trivy_done = any(ev.get("tool") == "trivy-image" and ev.get("type") == "done"
                     for ev in events)

    if not trivy_done:
        cve_verdict = "SKIPPED"
        cve_metric  = "trivy-image did not run"
    elif cve_critical > 0:
        cve_verdict = "WARNING"   # CVE-urile critice apar dar nu blocheaza (la fel ca in modul dockerfile)
        cve_metric  = f"{cve_critical} critical, {cve_high} high"
    elif cve_high >= _CVE_WARN_COUNT:
        cve_verdict = "WARNING"
        cve_metric  = f"{cve_high} high"
    else:
        cve_verdict = "PASS"
        cve_metric  = "0 critical, 0 high"

    verdicts = {
        "image_size":       _image_verdict_size(size_bytes),
        "layer_efficiency": _image_verdict_efficiency(efficiency),
        "wasted_space":     _image_verdict_wasted(wasted_bytes),
        "cve_findings":     cve_verdict,
    }
    metrics = {
        "image_size":       f"{size_bytes / 1024 / 1024:.1f} MB across {layer_count} layer(s)",
        "layer_efficiency": f"{efficiency * 100:.1f}%",
        "wasted_space":     f"{wasted_bytes / 1024 / 1024:.1f} MB wasted",
        "cve_findings":     cve_metric,
    }

    categories_out = {
        cat_id: {
            "label":       label,
            "description": desc,
            "verdict":     verdicts[cat_id],
            "metric":      metrics[cat_id],
        }
        for cat_id, label, desc in _IMAGE_CATEGORIES
    }

    seen = set(verdicts.values())
    if   "CRITICAL" in seen: overall = "POLICY_REJECTED"
    elif "WARNING"  in seen: overall = "WARNING"
    else:                    overall = "APPROVED"

    # `total_findings` = numarul de categorii non-PASS + numarul de CVE, pentru vizibilitate.
    non_pass_categories = sum(1 for v in verdicts.values() if v not in ("PASS", "SKIPPED"))
    total = non_pass_categories + cve_total

    return {
        "verdict":        overall,
        "total_findings": total,
        "image_summary": {
            "size_bytes":      size_bytes,
            "wasted_bytes":    wasted_bytes,
            "efficiency":      efficiency,
            "layer_count":     layer_count,
            "top_waste_files": top_waste,
            "cve_total":       cve_total,
            "cve_critical":    cve_critical,
            "cve_high":        cve_high,
        },
        "categories": categories_out,
    }
