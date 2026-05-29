# scaner de CVE pe pachete: incerc intai OSV.dev, daca pica trec pe NVD
# tot ce iese e marcat cu tool="package" ca interfata sa vada un singur scaner
import logging
from typing import AsyncGenerator

from services.osv_scanner import osv_health_check, scan_packages_osv
from services.nvd_scanner import scan_packages_nvd

logger = logging.getLogger("package_scanner")


async def scan_packages(
    packages: list[dict],
    display_name: str,
    dockerfile_content: str = "",
) -> AsyncGenerator[dict, None]:
    if not packages:
        yield {"tool": "package", "type": "info", "file": display_name,
               "message": "✓ No installable packages detected in RUN instructions"}
        yield {"tool": "package", "type": "done", "file": display_name,
               "message": "■ Package CVE scan complete — 0 packages to check",
               "count": 0, "source": "none"}
        return

    yield {"tool": "package", "type": "info", "file": display_name,
           "message": "▶ [package] Checking OSV.dev availability..."}

    if await osv_health_check():
        yield {"tool": "package", "type": "info", "file": display_name,
               "message": "  ✓ OSV.dev reachable — using as primary source",
               "source": "osv"}
        async for ev in scan_packages_osv(packages, display_name, dockerfile_content):
            ev = {**ev, "tool": "package", "source": "osv"}
            yield ev
        return

    # OSV nu raspunde, asa ca incerc NVD
    yield {"tool": "package", "type": "warning", "file": display_name,
           "message": "  ⚠ OSV.dev unreachable — falling back to NVD API",
           "source": "fallback"}
    logger.warning("OSV.dev unreachable, falling back to NVD")

    async for ev in scan_packages_nvd(packages, display_name):
        ev = {**ev, "tool": "package", "source": "nvd"}
        yield ev
