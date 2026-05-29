# scaner de CVE prin OSV.dev, sursa mea principala
# OSV stie pe ce ecosistem e pachetul (apt-get install curl pe Debian = Debian:curl,
# nu curl generic) si aduna 24+ surse, deci da mult mai putine alarme false ca NVD
import asyncio
import json
import logging
import urllib.request
from typing import AsyncGenerator

from services.pkg_parser import OSV_ECOSYSTEMS, _parse_from_distro

logger = logging.getLogger("osv_scanner")

OSV_API_URL = "https://api.osv.dev/v1/query"
OSV_TIMEOUT = 10  # seconds per request

# Severity → our internal level. OSV uses these strings in
# database_specific.severity for Debian/Alpine records.
SEVERITY_TO_LEVEL = {
    "CRITICAL": "critical",
    "HIGH":     "high",
    "MEDIUM":   "medium",
    "MODERATE": "medium",  # asa apare in GitHub Advisory
    "LOW":      "low",
}


def _resolve_ecosystem(manager: str, distro_hint: str | None) -> str:
    # caut numele ecosistemului OSV; pentru apt il fac mai precis spre Debian/Ubuntu
    base = OSV_ECOSYSTEMS.get(manager, "")
    if manager == "apt" and distro_hint:
        return distro_hint
    return base


async def _query_osv(name: str, ecosystem: str, version: str | None) -> dict:
    # interoghez OSV pentru un singur pachet
    payload = {"package": {"name": name, "ecosystem": ecosystem}}
    if version:
        payload["version"] = version

    req = urllib.request.Request(
        OSV_API_URL,
        data=json.dumps(payload).encode(),
        headers={
            "Content-Type": "application/json",
            "User-Agent":   "DockerHardeningHub/0.8 (osv-scanner)",
        },
        method="POST",
    )

    # urllib blocheaza, asa ca il mut pe un thread ca sa nu opresc bucla
    def _do():
        with urllib.request.urlopen(req, timeout=OSV_TIMEOUT) as resp:
            return json.loads(resp.read().decode())

    return await asyncio.to_thread(_do)


async def osv_health_check() -> bool:
    # verific rapid daca OSV raspunde, ca sa stiu daca-l folosesc sau trec pe NVD
    try:
        await _query_osv("curl", "Debian", None)
        return True
    except Exception as exc:
        logger.warning("OSV.dev health check failed: %s", exc)
        return False


def _extract_severity(vuln: dict) -> str:
    # OSV pune severitatea in locuri diferite, depinde de sursa
    db = vuln.get("database_specific") or {}
    if isinstance(db, dict):
        sev = db.get("severity")
        if sev:
            return SEVERITY_TO_LEVEL.get(sev.upper(), "medium")

    # daca nu, ma uit la vectorii CVSS din severity[]
    for entry in vuln.get("severity", []) or []:
        score = entry.get("score", "")
        if "C:H/I:H/A:H" in score or "CRITICAL" in score.upper():
            return "critical"
    return "medium"


async def scan_packages_osv(
    packages: list[dict], display_name: str, dockerfile_content: str = "",
) -> AsyncGenerator[dict, None]:
    if not packages:
        yield {"tool": "osv", "type": "info", "file": display_name,
               "message": "✓ No installable packages detected in RUN instructions"}
        return

    distro = _parse_from_distro(dockerfile_content) if dockerfile_content else None
    if distro:
        logger.info("OSV: detected base distro = %s", distro)

    yield {"tool": "osv", "type": "start", "file": display_name,
           "message": f"▶ [osv] Querying OSV.dev for {len(packages)} package(s)..."}

    total = 0
    skipped_unpinned = 0
    for pkg in packages:
        name = pkg["name"]
        ecosystem = _resolve_ecosystem(pkg["manager"], distro)

        if not ecosystem:
            yield {"tool": "osv", "type": "info", "file": display_name,
                   "message": f"  ⚠ {name} — no OSV ecosystem mapping for {pkg['manager']}"}
            continue

        # daca pachetul n-are versiune fixata, il sar
        # Hadolint (DL3008 etc.) si CIS-4.4 semnaleaza deja lipsa versiunii
        # fara versiune, OSV ar intoarce tot istoricul de CVE, zgomotos si inutil
        if not pkg.get("version"):
            skipped_unpinned += 1
            yield {"tool": "osv", "type": "info", "file": display_name,
                   "message": f"  → {name}@{ecosystem} — skipped (no version pin; "
                              f"see DL3008/CIS-4.4 to enable scanning)"}
            continue

        try:
            data = await _query_osv(name, ecosystem, pkg.get("version"))
        except Exception as exc:
            logger.warning("OSV lookup failed for %s: %s", name, exc)
            yield {"tool": "osv", "type": "info", "file": display_name,
                   "message": f"  ⚠ {name} — OSV lookup failed: {str(exc)[:80]}"}
            continue

        severe = [
            (v, _extract_severity(v))
            for v in (data.get("vulns") or [])
            if _extract_severity(v) in ("critical", "high")
        ]

        if not severe:
            yield {"tool": "osv", "type": "info", "file": display_name,
                   "message": f"  ✓ {name}@{ecosystem} — no critical/high vulns found"}
            continue

        # arat primele 3, restul le rezum daca sunt mai multe
        for vuln, level in severe[:3]:
            vid = vuln.get("id", "OSV-?")
            summary = (vuln.get("summary") or vuln.get("details") or "")[:120]
            total += 1
            yield {"tool": "osv", "type": "issue", "file": display_name,
                   "level": level, "code": vid,
                   "message": f"[{level.upper()}] {vid} ({name}@{ecosystem}): {summary}"}
        if len(severe) > 3:
            yield {"tool": "osv", "type": "info", "file": display_name,
                   "message": f"  ... and {len(severe) - 3} more for {name}"}

    done_msg = f"■ OSV scan complete — {total} known vulnerability(ies)"
    if skipped_unpinned:
        done_msg += f"  ·  {skipped_unpinned} unpinned package(s) skipped"
    yield {"tool": "osv", "type": "done", "file": display_name,
           "message": done_msg,
           "count": total}
