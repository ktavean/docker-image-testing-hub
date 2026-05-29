# scaner Dive: ma uit la eficienta straturilor unei imagini deja construite
# nu construiesc niciodata Dockerfile-ul aici; imaginea vine fie ca arhiva
# docker-archive deja pe disc, fie ca referinta de registru pe care o aduce
# skopeo ca arhiva (fara demon)
# forma intrarii:
#   {"kind": "tarball", "path": "/tmp/.../<uuid>.tar"}
#   {"kind": "ref",     "ref":  "nginx:1.27-alpine"}
import asyncio
import json
import os
import uuid
from typing import AsyncGenerator

from services.scanner import _run   # ajutorul comun pentru subprocese

SKOPEO_TIMEOUT    = 180
DIVE_TIMEOUT      = 240
MAX_TARBALL_BYTES = 1 * 1024 * 1024 * 1024   # 1 GB hard ceiling
TOP_WASTE_FILES   = 5

# praguri, le tin la fel ca in scoring._image_verdict_*
SIZE_WARN_BYTES   = 1024 * 1024 * 1024
SIZE_INFO_BYTES   = 500  * 1024 * 1024
EFFICIENCY_WARN   = 0.95
EFFICIENCY_CRIT   = 0.85
WASTED_WARN_BYTES = 50  * 1024 * 1024
WASTED_CRIT_BYTES = 200 * 1024 * 1024


def _human_size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _classify(metric: str, value) -> str:
    # transform valoarea unei metrici intr-un nivel de severitate pentru consola
    if metric == "size":
        return "warning" if value > SIZE_WARN_BYTES else "info"
    if metric == "efficiency":
        if value < EFFICIENCY_CRIT: return "critical"
        if value < EFFICIENCY_WARN: return "warning"
        return "info"
    if metric == "wasted":
        if value > WASTED_CRIT_BYTES: return "critical"
        if value > WASTED_WARN_BYTES: return "warning"
        return "info"
    return "info"


def _issue(file: str, level: str, code: str, msg: str) -> dict:
    return {"tool": "dive", "type": "issue", "file": file,
            "level": level, "code": code, "message": msg}


def _ref_path(ref: dict) -> str:
    # scot calea dintr-o intrare fileReference
    # in JSON-ul Dive campul se cheama "file"; "path"/"Path" sunt variante
    # pentru versiuni mai vechi, iar "?" e ultima solutie daca lipsesc toate
    return ref.get("file") or ref.get("path") or ref.get("Path") or "?"


def _err_done(file: str, err_msg: str, abort_msg: str) -> list[dict]:
    # un eveniment de eroare plus un done fara sumar, ca sa ies curat
    return [
        {"tool": "dive", "type": "error", "file": file, "message": err_msg},
        {"tool": "dive", "type": "done",  "file": file, "message": abort_msg,
         "count": 0, "summary": None},
    ]


async def _resolve_tarball(
    image_input: dict, file: str,
) -> tuple[str | None, bool, list[dict]]:
    # obtin o arhiva docker-archive pe disc pe care o poate citi dive
    # intorc (cale, trebuie_sters, evenimente); daca calea e None, evenimentele
    # contin erorile de afisat utilizatorului
    kind = image_input.get("kind")

    if kind == "tarball":
        path = image_input["path"]
        if not os.path.exists(path):
            return None, False, _err_done(
                file, f"✗ Tarball not found on disk: {path}",
                "■ Dive aborted — missing tarball")
        return path, False, []

    if kind == "ref":
        ref  = image_input["ref"]
        path = f"/tmp/dive_{uuid.uuid4().hex}.tar"
        prelude = [{"tool": "dive", "type": "info", "file": file,
                    "message": f"  ↓ Pulling {ref} via skopeo (no daemon)..."}]
        _, err, rc = await _run(
            ["skopeo", "copy", f"docker://{ref}", f"docker-archive:{path}"],
            timeout=SKOPEO_TIMEOUT,
        )
        if rc != 0:
            msg = err.decode(errors="replace").strip()[:300] if err else "unknown skopeo error"
            return None, True, prelude + _err_done(
                file, f"✗ Pull failed: {msg}",
                "■ Dive aborted — image could not be pulled")
        return path, True, prelude

    return None, False, _err_done(
        file, f"✗ Unknown image_input kind: {kind!r}",
        "■ Dive aborted — invalid input")


async def stream_dive(image_input: dict, display_name: str) -> AsyncGenerator[dict, None]:
    # rulez dive pe o imagine; emit start, info, probleme, done
    yield {"tool": "dive", "type": "start", "file": display_name,
           "message": f"▶ [dive] Analyzing image {display_name}..."}

    tar_path, cleanup, prelude = await _resolve_tarball(image_input, display_name)
    for ev in prelude:
        yield ev
    if tar_path is None:
        return

    try:
        size = os.path.getsize(tar_path)
        if size > MAX_TARBALL_BYTES:
            for ev in _err_done(
                display_name,
                f"✗ Image too large ({_human_size(size)} > 1 GB ceiling)",
                "■ Dive aborted — image exceeds size ceiling",
            ):
                yield ev
            return

        yield {"tool": "dive", "type": "info", "file": display_name,
               "message": f"  ↳ Tarball ready ({_human_size(size)}), invoking dive..."}

        # dive intoarce cod non-zero cand pica regulile lui de CI (eficienta
        # sub prag etc.), ceea ce e normal; pe mine ma intereseaza fisierul JSON
        # tratez ca eroare doar lipsa JSON-ului
        json_out = f"/tmp/dive_{uuid.uuid4().hex}.json"
        try:
            _, err, _ = await _run(
                ["dive", "--source", "docker-archive",
                 "--ci", "--json", json_out, tar_path],
                timeout=DIVE_TIMEOUT,
            )
            if not os.path.exists(json_out):
                err_str = err.decode(errors="replace").strip()[:300] if err else "no output"
                for ev in _err_done(display_name, f"✗ Dive produced no JSON: {err_str}",
                                    "■ Dive failed"):
                    yield ev
                return
            with open(json_out, "r", encoding="utf-8") as f:
                data = json.load(f)
        finally:
            try: os.unlink(json_out)
            except OSError: pass

        # schema JSON a lui Dive s-a schimbat intre versiuni, asa ca verific
        # si numele vechi si cele noi ale cheilor
        img          = data.get("image", {}) or {}
        total_bytes  = int(img.get("sizeBytes", 0) or 0)
        wasted_bytes = int(img.get("inefficientBytes", 0) or 0)
        efficiency   = float(img.get("efficiencyScore", img.get("efficiency", 1.0)) or 1.0)
        # versiunile noi nu mai dau userWastedPercent, asa ca-l calculez singur
        # ma feresc de impartire la zero cand totalul lipseste
        wasted_pct   = (wasted_bytes / total_bytes) if total_bytes else 0.0
        file_refs    = img.get("fileReference") or img.get("inefficientFiles") or []
        layer_count  = len(data.get("layer") or [])

        yield _issue(display_name, _classify("size", total_bytes), "image-size",
                     f"■ Total size: {_human_size(total_bytes)} across {layer_count} layer(s)")
        yield _issue(display_name, _classify("efficiency", efficiency), "efficiency",
                     f"■ Layer efficiency: {efficiency * 100:.1f}%")
        yield _issue(display_name, _classify("wasted", wasted_bytes), "wasted-bytes",
                     f"■ Wasted space: {_human_size(wasted_bytes)} "
                     f"({wasted_pct * 100:.1f}% of image)")

        if file_refs:
            yield {"tool": "dive", "type": "info", "file": display_name,
                   "message": f"  Top {min(TOP_WASTE_FILES, len(file_refs))} wasted-space file(s):"}
            for ref in file_refs[:TOP_WASTE_FILES]:
                path  = _ref_path(ref)
                rsize = int(ref.get("sizeBytes") or ref.get("cumulativeSize") or 0)
                count = int(ref.get("count")     or ref.get("references")     or 1)
                yield _issue(display_name, "info", "waste-file",
                             f"  · {path} — {_human_size(rsize)} across {count} layer(s)")

        yield {
            "tool": "dive", "type": "done", "file": display_name,
            "message": (
                f"■ Dive complete — {_human_size(total_bytes)} total, "
                f"{efficiency * 100:.1f}% efficient, {_human_size(wasted_bytes)} wasted"
            ),
            "count": 3,
            "summary": {
                "size_bytes":      total_bytes,
                "wasted_bytes":    wasted_bytes,
                "efficiency":      efficiency,
                "user_wasted_pct": wasted_pct,
                "layer_count":     layer_count,
                "top_waste_files": [{
                    "path":  _ref_path(r),
                    "size":  int(r.get("sizeBytes") or r.get("cumulativeSize") or 0),
                    "count": int(r.get("count")     or r.get("references")     or 1),
                } for r in file_refs[:TOP_WASTE_FILES]],
            },
        }

    except asyncio.CancelledError:
        raise   # las procesul de lucru sa duca mai departe anularea
    except Exception as exc:
        for ev in _err_done(display_name, f"✗ Dive scanner error: {exc!s}", "■ Dive failed"):
            yield ev
    finally:
        # sterg doar arhivele aduse de mine; pe cele incarcate de utilizator
        # le curata procesul de lucru dupa ce se termina tot jobul
        if cleanup and tar_path:
            try: os.unlink(tar_path)
            except OSError: pass
