# scaner de CVE prin NVD, il folosesc cand OSV.dev nu raspunde
# caut dupa nume CPE acolo unde am o corespondenta (~100 pachete),
# iar in rest caut dupa cuvinte cheie; cautarea dupa cuvinte e zgomotoasa
# dar e singura optiune generala pe care o ofera NVD
import logging
import os
from typing import AsyncGenerator

try:
    import nvdlib
except ImportError:
    nvdlib = None

logger = logging.getLogger("nvd_scanner")

NVD_API_KEY_ENV = "NVD_API_KEY"

CVSS_TO_LEVEL = {
    "CRITICAL": "critical",
    "HIGH":     "high",
    "MEDIUM":   "medium",
    "LOW":      "low",
}

# corespondenta pachet -> identificator CPE 2.3
# cautarea dupa cuvinte a NVD e prea zgomotoasa, asa ca tin maparea asta
# pentru pachetele instalate de obicei; ce nu e aici cade pe cautarea dupa cuvinte
# TODO: de extins pe masura ce apar pachete noi in scanari
CPE_MAP: dict[str, str] = {
    # servere web / proxy
    "nginx":          "cpe:2.3:a:f5:nginx",
    "apache2":        "cpe:2.3:a:apache:http_server",
    "httpd":          "cpe:2.3:a:apache:http_server",
    "haproxy":        "cpe:2.3:a:haproxy:haproxy",
    "varnish":        "cpe:2.3:a:varnish-cache:varnish",
    "lighttpd":       "cpe:2.3:a:lighttpd:lighttpd",
    "envoy":          "cpe:2.3:a:envoyproxy:envoy",

    # tls / criptografie
    "openssl":        "cpe:2.3:a:openssl:openssl",
    "libssl-dev":     "cpe:2.3:a:openssl:openssl",
    "libssl":         "cpe:2.3:a:openssl:openssl",
    "gnutls":         "cpe:2.3:a:gnu:gnutls",
    "libgcrypt":      "cpe:2.3:a:gnu:libgcrypt",
    "nss":            "cpe:2.3:a:mozilla:network_security_services",

    # retea / transfer
    "curl":           "cpe:2.3:a:haxx:curl",
    "libcurl":        "cpe:2.3:a:haxx:curl",
    "libcurl4":       "cpe:2.3:a:haxx:curl",
    "wget":           "cpe:2.3:a:gnu:wget",
    "openssh-server": "cpe:2.3:a:openbsd:openssh",
    "openssh-client": "cpe:2.3:a:openbsd:openssh",
    "ssh":            "cpe:2.3:a:openbsd:openssh",
    "rsync":          "cpe:2.3:a:samba:rsync",

    # baze de date
    "postgresql":     "cpe:2.3:a:postgresql:postgresql",
    "mysql-server":   "cpe:2.3:a:oracle:mysql",
    "mysql":          "cpe:2.3:a:oracle:mysql",
    "mariadb-server": "cpe:2.3:a:mariadb:mariadb",
    "mariadb":        "cpe:2.3:a:mariadb:mariadb",
    "redis":          "cpe:2.3:a:redislabs:redis",
    "redis-server":   "cpe:2.3:a:redislabs:redis",
    "mongodb":        "cpe:2.3:a:mongodb:mongodb",
    "memcached":      "cpe:2.3:a:memcached:memcached",
    "sqlite3":        "cpe:2.3:a:sqlite:sqlite",
    "libsqlite3":     "cpe:2.3:a:sqlite:sqlite",

    # limbaje / medii de rulare
    "python":         "cpe:2.3:a:python:python",
    "python3":        "cpe:2.3:a:python:python",
    "python3-pip":    "cpe:2.3:a:python:python",
    "python3.10":     "cpe:2.3:a:python:python",
    "python3.11":     "cpe:2.3:a:python:python",
    "python3.12":     "cpe:2.3:a:python:python",
    "ruby":           "cpe:2.3:a:ruby-lang:ruby",
    "perl":           "cpe:2.3:a:perl:perl",
    "php":            "cpe:2.3:a:php:php",
    "php-cli":        "cpe:2.3:a:php:php",
    "php-fpm":        "cpe:2.3:a:php:php",
    "nodejs":         "cpe:2.3:a:nodejs:node.js",
    "node":           "cpe:2.3:a:nodejs:node.js",
    "openjdk-17-jre": "cpe:2.3:a:oracle:openjdk",
    "openjdk-17-jdk": "cpe:2.3:a:oracle:openjdk",
    "default-jre":    "cpe:2.3:a:oracle:openjdk",
    "default-jdk":    "cpe:2.3:a:oracle:openjdk",
    "golang":         "cpe:2.3:a:golang:go",

    # editoare / shell-uri
    "vim":            "cpe:2.3:a:vim:vim",
    "vim-tiny":       "cpe:2.3:a:vim:vim",
    "nano":           "cpe:2.3:a:gnu:nano",
    "bash":           "cpe:2.3:a:gnu:bash",
    "zsh":            "cpe:2.3:a:zsh:zsh",
    "tmux":           "cpe:2.3:a:tmux_project:tmux",

    # imagini / multimedia
    "imagemagick":    "cpe:2.3:a:imagemagick:imagemagick",
    "libpng":         "cpe:2.3:a:libpng:libpng",
    "libjpeg":        "cpe:2.3:a:ijg:libjpeg",
    "libtiff":        "cpe:2.3:a:libtiff:libtiff",
    "ffmpeg":         "cpe:2.3:a:ffmpeg:ffmpeg",
    "libavcodec":     "cpe:2.3:a:ffmpeg:ffmpeg",

    # compresie / xml
    "zlib1g":         "cpe:2.3:a:zlib:zlib",
    "libxml2":        "cpe:2.3:a:xmlsoft:libxml2",
    "libxslt":        "cpe:2.3:a:xmlsoft:libxslt",
    "p7zip":          "cpe:2.3:a:7-zip:7-zip",
    "tar":            "cpe:2.3:a:gnu:tar",

    # librarii de sistem
    "libc6":          "cpe:2.3:a:gnu:glibc",
    "glibc":          "cpe:2.3:a:gnu:glibc",
    "musl":           "cpe:2.3:a:musl-libc:musl",
    "systemd":        "cpe:2.3:a:systemd_project:systemd",
    "git":            "cpe:2.3:a:git-scm:git",
    "subversion":     "cpe:2.3:a:apache:subversion",

    # unelte pentru containere
    "docker.io":      "cpe:2.3:a:docker:docker",
    "containerd":     "cpe:2.3:a:linuxfoundation:containerd",
    "podman":         "cpe:2.3:a:podman_project:podman",

    # librarii python uzuale (pentru pip)
    "django":         "cpe:2.3:a:djangoproject:django",
    "flask":          "cpe:2.3:a:palletsprojects:flask",
    "requests":       "cpe:2.3:a:python:requests",
    "urllib3":        "cpe:2.3:a:python:urllib3",
    "pyyaml":         "cpe:2.3:a:pyyaml:pyyaml",
    "jinja2":         "cpe:2.3:a:palletsprojects:jinja",
    "cryptography":   "cpe:2.3:a:cryptography_project:cryptography",
    "pillow":         "cpe:2.3:a:python:pillow",
    "lxml":           "cpe:2.3:a:lxml:lxml",
    "numpy":          "cpe:2.3:a:numpy:numpy",

    # librarii npm uzuale
    "express":        "cpe:2.3:a:openjsf:express",
    "lodash":         "cpe:2.3:a:lodash:lodash",
    "axios":          "cpe:2.3:a:axios:axios",
    "react":          "cpe:2.3:a:facebook:react",
}


def _cve_severity(cve) -> str:
    # nvdlib da fie CVSS v31 fie v2, depinde de CVE
    return (getattr(cve, "v31severity", None)
            or getattr(cve, "v2severity", None)
            or "")


async def scan_packages_nvd(
    packages: list[dict], display_name: str,
) -> AsyncGenerator[dict, None]:
    if not nvdlib:
        yield {"tool": "nvd", "type": "error", "file": display_name,
               "message": "nvdlib not installed — skipping NVD lookup"}
        return
    if not packages:
        yield {"tool": "nvd", "type": "info", "file": display_name,
               "message": "✓ No installable packages detected in RUN instructions"}
        return

    yield {"tool": "nvd", "type": "start", "file": display_name,
           "message": f"▶ [nvd] Fallback: querying NVD for {len(packages)} package(s)..."}

    api_key = os.environ.get(NVD_API_KEY_ENV)
    base_kwargs = {"key": api_key, "delay": 0.6} if api_key else {}
    if not api_key:
        logger.info("NVD: no API key — using default rate limit")

    total = 0
    cpe_hits = keyword_hits = 0
    skipped_unpinned = 0

    for pkg in packages:
        name = pkg["name"]

        # aceeasi regula ca la OSV: nu scanez pachete fara versiune fixata
        # Hadolint si CIS-4.4 semnaleaza deja lipsa versiunii
        # fara versiune, NVD ar da tot istoricul de CVE
        if not pkg.get("version"):
            skipped_unpinned += 1
            yield {"tool": "nvd", "type": "info", "file": display_name,
                   "message": f"  → {name} — skipped (no version pin; "
                              f"see DL3008/CIS-4.4 to enable scanning)"}
            continue

        cpe = CPE_MAP.get(name.lower())

        kwargs = dict(base_kwargs)
        if cpe:
            kwargs["cpeName"] = cpe
            kwargs["isVulnerable"] = True
            cpe_hits += 1
        else:
            kwargs["keywordSearch"] = name
            keyword_hits += 1

        try:
            results = list(nvdlib.searchCVE(**kwargs))
        except Exception as exc:
            logger.warning("NVD lookup failed for %s: %s", name, exc)
            yield {"tool": "nvd", "type": "info", "file": display_name,
                   "message": f"  ⚠ {name} — NVD lookup failed: {str(exc)[:80]}"}
            continue

        severe = [c for c in results if _cve_severity(c).upper() in ("CRITICAL", "HIGH")]

        if not severe:
            yield {"tool": "nvd", "type": "info", "file": display_name,
                   "message": f"  ✓ {name} — no critical/high CVEs found"}
            continue

        method = "CPE" if cpe else "keyword"
        for cve in severe[:3]:
            sev = _cve_severity(cve) or "UNKNOWN"
            desc = ""
            if getattr(cve, "descriptions", None):
                desc = cve.descriptions[0].value[:120]
            total += 1
            yield {"tool": "nvd", "type": "issue", "file": display_name,
                   "level": CVSS_TO_LEVEL.get(sev.upper(), "medium"),
                   "code": cve.id,
                   "message": f"[{sev}] {cve.id} ({name} via {method}): {desc}"}
        if len(severe) > 3:
            yield {"tool": "nvd", "type": "info", "file": display_name,
                   "message": f"  ... and {len(severe) - 3} more for {name}"}

    yield {"tool": "nvd", "type": "info", "file": display_name,
           "message": f"  Lookup methods: {cpe_hits} CPE-based, {keyword_hits} keyword-based"}
    done_msg = f"■ NVD fallback complete — {total} known vulnerability(ies)"
    if skipped_unpinned:
        done_msg += f"  ·  {skipped_unpinned} unpinned package(s) skipped"
    yield {"tool": "nvd", "type": "done", "file": display_name,
           "message": done_msg,
           "count": total}
