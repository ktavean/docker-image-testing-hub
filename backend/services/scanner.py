# pipeline-urile de scanare; fiecare stream_* e un generator asincron care
# emite evenimente de forma {tool, type, file, ...}
# orchestratorul de la final le combina pe tip de fisier si trimite rezultatul
# mai departe la procesul de lucru
import asyncio
import json
import math
import os
import re
from collections import Counter
from typing import AsyncGenerator

from services.pkg_parser import parse_packages_from_dockerfile
from services.package_scanner import scan_packages
from services.cis_advisor import stream_cis_advisor
from services.compose_advisor import stream_compose_advisor, extract_images


# clasificarea fisierelor

def classify_file(filename: str) -> str:
    base = os.path.basename(filename).lower()
    if base.startswith("dockerfile") or base.endswith(".dockerfile"):
        return "dockerfile"
    is_compose = (base.startswith("docker-compose")
                  or base in ("compose.yml", "compose.yaml"))
    if is_compose and base.endswith((".yml", ".yaml")):
        return "compose"
    return "unknown"


def _parse_from_image(content: str) -> str | None:
    # scot imaginea de baza din ultimul FROM al unui Dockerfile
    last = None
    for line in content.splitlines():
        s = line.strip()
        if s.upper().startswith("FROM "):
            parts = s.split()
            if len(parts) >= 2:
                last = parts[1]
    return last


async def _run(command: list[str], timeout: int = 60) -> tuple[bytes, bytes, int]:
    # rulez un subproces cu o limita de timp; intorc (stdout, stderr, cod)
    try:
        proc = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return stdout, stderr, proc.returncode
    except asyncio.TimeoutError:
        try: proc.kill()
        except Exception: pass
        return b"", b"Timed out", 1
    except FileNotFoundError:
        return b"", f"{command[0]!r} not found".encode(), 127


# Hadolint

async def stream_hadolint(file_path: str, display_name: str) -> AsyncGenerator[dict, None]:
    yield {"tool": "hadolint", "type": "start", "file": display_name,
           "message": f"▶ [hadolint] Linting {display_name}..."}

    stdout, _, _ = await _run(["hadolint", "--format", "json", file_path])

    issues = []
    if stdout:
        try:
            raw = json.loads(stdout.decode())
            issues = raw if isinstance(raw, list) else []
        except json.JSONDecodeError:
            yield {"tool": "hadolint", "type": "info", "file": display_name,
                   "message": stdout.decode()[:500]}

    for issue in issues:
        yield {
            "tool": "hadolint", "type": "issue", "file": display_name,
            "level": issue.get("level", "info"),
            "code": issue.get("code", ""),
            "line": issue.get("line", 0),
            "message": f"[Line {issue.get('line', 0)}] {issue.get('code', '')}: {issue.get('message', '')}",
        }

    if not issues:
        yield {"tool": "hadolint", "type": "info", "file": display_name,
               "message": "✓ No issues found"}
    yield {"tool": "hadolint", "type": "done", "file": display_name,
           "message": f"■ Hadolint complete — {len(issues)} issue(s)",
           "count": len(issues)}


# Trivy config (scanare de configurari gresite)

async def stream_trivy_config(file_path: str, display_name: str) -> AsyncGenerator[dict, None]:
    yield {"tool": "trivy", "type": "start", "file": display_name,
           "message": f"▶ [trivy] Config scan {display_name}..."}

    stdout, _, _ = await _run(["trivy", "config", "--format", "json", "--quiet", file_path])

    count = 0
    if stdout:
        try:
            data = json.loads(stdout.decode())
            for result in data.get("Results", []):
                for m in (result.get("Misconfigurations") or []):
                    count += 1
                    sev = m.get("Severity", "UNKNOWN")
                    yield {
                        "tool": "trivy", "type": "issue", "file": display_name,
                        "level": sev.lower(),
                        "code": m.get("ID", ""),
                        "message": f"[{sev}] {m.get('Title', '')}: {m.get('Message', '')}",
                    }
        except json.JSONDecodeError:
            yield {"tool": "trivy", "type": "info", "file": display_name,
                   "message": stdout.decode()[:500]}

    if count == 0:
        yield {"tool": "trivy", "type": "info", "file": display_name,
               "message": "✓ No misconfigurations found"}
    yield {"tool": "trivy", "type": "done", "file": display_name,
           "message": f"■ Trivy config complete — {count} issue(s)", "count": count}


# Trivy image (imaginea de baza / imaginile din compose)

async def _scan_one_image(
    image: str, display_name: str, source_label: str,
) -> AsyncGenerator[dict, None]:
    yield {"tool": "trivy-image", "type": "start", "file": display_name,
           "message": f"▶ [trivy-image] Scanning {source_label}: {image}..."}

    stdout, stderr, rc = await _run(
        ["trivy", "image", "--format", "json", "--quiet",
         "--severity", "CRITICAL,HIGH", image],
        timeout=120,
    )

    count = 0
    if stdout:
        try:
            data = json.loads(stdout.decode())
            for result in data.get("Results", []):
                for vuln in (result.get("Vulnerabilities") or []):
                    count += 1
                    sev = vuln.get("Severity", "UNKNOWN")
                    pkg = vuln.get("PkgName", "?")
                    vid = vuln.get("VulnerabilityID", "?")
                    title = vuln.get("Title", vuln.get("Description", ""))[:100]
                    yield {
                        "tool": "trivy-image", "type": "issue", "file": display_name,
                        "level": sev.lower(), "code": vid,
                        "message": f"[{sev}] {vid} in {pkg} ({image}): {title}",
                        "image": image,
                    }
        except json.JSONDecodeError:
            yield {"tool": "trivy-image", "type": "info", "file": display_name,
                   "message": f"Could not parse Trivy output for {image}: {stdout.decode()[:200]}"}

    if rc != 0 and count == 0:
        err = stderr.decode().strip()[:200] if stderr else "unknown error"
        yield {"tool": "trivy-image", "type": "info", "file": display_name,
               "message": f"⚠ Image scan ({image}) returned errors: {err}"}

    if count == 0:
        yield {"tool": "trivy-image", "type": "info", "file": display_name,
               "message": f"✓ No critical/high CVEs in {image}"}

    # image_done e un marcaj intern; apelantul le aduna intr-un total
    yield {"tool": "trivy-image", "type": "image_done", "file": display_name,
           "message": f"  · {image}: {count} CVE(s)", "count": count, "image": image}


async def stream_trivy_image(content: str, display_name: str) -> AsyncGenerator[dict, None]:
    # scanez imaginea din FROM-ul unui Dockerfile
    base = _parse_from_image(content)
    if not base or base.lower() == "scratch":
        yield {"tool": "trivy-image", "type": "info", "file": display_name,
               "message": "✓ No scannable base image (scratch or none)"}
        yield {"tool": "trivy-image", "type": "done", "file": display_name,
               "message": "■ Base image scan skipped", "count": 0}
        return

    total = 0
    async for ev in _scan_one_image(base, display_name, "base image"):
        if ev.get("type") == "image_done":
            total += ev.get("count", 0)
            continue  # nu trimit mai departe marcajul intern
        yield ev

    yield {"tool": "trivy-image", "type": "done", "file": display_name,
           "message": f"■ Base image scan complete — {total} CVE(s)", "count": total}


async def stream_trivy_for_image_input(
    image_input: dict, display_name: str,
) -> AsyncGenerator[dict, None]:
    # scanare Trivy pe o intrare de tip imagine (kind=tarball sau kind=ref)
    # arhivele folosesc `trivy image --input <cale>`, iar referintele de registru
    # `trivy image <ref>` direct; trivy face singur descarcarea fara demon,
    # deci nu trebuie sa trec prin skopeo cum face dive
    kind = image_input.get("kind")
    yield {"tool": "trivy-image", "type": "start", "file": display_name,
           "message": f"▶ [trivy-image] Scanning {display_name}..."}

    if kind == "tarball":
        path = image_input.get("path")
        if not path or not os.path.exists(path):
            yield {"tool": "trivy-image", "type": "info", "file": display_name,
                   "message": f"✗ Tarball not found on disk: {path}"}
            yield {"tool": "trivy-image", "type": "done", "file": display_name,
                   "message": "■ Trivy aborted — missing tarball", "count": 0}
            return
        cmd = ["trivy", "image", "--format", "json", "--quiet",
               "--severity", "CRITICAL,HIGH", "--input", path]
        source = f"docker-archive:{os.path.basename(path)}"
    elif kind == "ref":
        ref = image_input.get("ref")
        if not ref:
            yield {"tool": "trivy-image", "type": "info", "file": display_name,
                   "message": "✗ Image reference missing"}
            yield {"tool": "trivy-image", "type": "done", "file": display_name,
                   "message": "■ Trivy aborted — missing ref", "count": 0}
            return
        cmd = ["trivy", "image", "--format", "json", "--quiet",
               "--severity", "CRITICAL,HIGH", ref]
        source = ref
    else:
        yield {"tool": "trivy-image", "type": "info", "file": display_name,
               "message": f"✗ Unknown image_input kind: {kind!r}"}
        yield {"tool": "trivy-image", "type": "done", "file": display_name,
               "message": "■ Trivy aborted — invalid input", "count": 0}
        return

    stdout, stderr, rc = await _run(cmd, timeout=180)

    count = 0
    if stdout:
        try:
            data = json.loads(stdout.decode())
            for result in data.get("Results", []):
                for vuln in (result.get("Vulnerabilities") or []):
                    count += 1
                    sev = vuln.get("Severity", "UNKNOWN")
                    pkg = vuln.get("PkgName", "?")
                    vid = vuln.get("VulnerabilityID", "?")
                    title = vuln.get("Title", vuln.get("Description", ""))[:100]
                    yield {
                        "tool": "trivy-image", "type": "issue", "file": display_name,
                        "level": sev.lower(), "code": vid,
                        "message": f"[{sev}] {vid} in {pkg} ({source}): {title}",
                        "image": source,
                    }
        except json.JSONDecodeError:
            yield {"tool": "trivy-image", "type": "info", "file": display_name,
                   "message": f"Could not parse Trivy output: {stdout.decode()[:200]}"}

    if rc != 0 and count == 0:
        err = stderr.decode().strip()[:200] if stderr else "unknown error"
        yield {"tool": "trivy-image", "type": "info", "file": display_name,
               "message": f"⚠ Trivy returned errors: {err}"}

    yield {"tool": "trivy-image", "type": "done", "file": display_name,
           "message": f"■ Image scan complete — {count} CVE(s)", "count": count}

    # generare SBOM (CycloneDX)
    # a doua invocare Trivy, de data asta cer un SBOM in format CycloneDX
    # baza de date e deja in cache de la scanarea CVE, asa ca e rapid
    # pun SBOM-ul direct in eveniment, ca frontendul sa-l ofere la descarcare
    # fara o ruta separata
    yield {"tool": "sbom", "type": "start", "file": display_name,
           "message": "▶ [sbom] Generating CycloneDX SBOM..."}

    sbom_cmd = ["trivy", "image", "--format", "cyclonedx", "--quiet"]
    if kind == "tarball":
        sbom_cmd += ["--input", image_input["path"]]
    else:
        sbom_cmd += [image_input["ref"]]

    sbom_out, sbom_err, sbom_rc = await _run(sbom_cmd, timeout=180)

    if sbom_rc != 0 or not sbom_out:
        err = sbom_err.decode().strip()[:200] if sbom_err else "no output"
        yield {"tool": "sbom", "type": "done", "file": display_name,
               "message": f"■ SBOM generation failed: {err}", "count": 0}
        return

    try:
        sbom_doc = json.loads(sbom_out.decode())
        components_count = len(sbom_doc.get("components") or [])
    except json.JSONDecodeError:
        yield {"tool": "sbom", "type": "done", "file": display_name,
               "message": "■ SBOM generation failed: could not parse CycloneDX JSON",
               "count": 0}
        return

    # bag textul SBOM in eveniment; frontendul il salveaza cu inregistrarea
    # scanarii si il ofera printr-un buton "Download SBOM"
    yield {
        "tool":    "sbom",
        "type":    "result",
        "file":    display_name,
        "format":  "cyclonedx",
        "components_count": components_count,
        "content": sbom_out.decode(),
        "message": f"■ SBOM ready — {components_count} component(s) catalogued",
    }
    yield {"tool": "sbom", "type": "done", "file": display_name,
           "message": "■ SBOM emission complete", "count": components_count}



async def stream_trivy_compose_images(
    content: str, display_name: str,
) -> AsyncGenerator[dict, None]:
    # scanez fiecare imagine referita prin `image:` intr-un fisier compose
    images = extract_images(content)
    if not images:
        yield {"tool": "trivy-image", "type": "info", "file": display_name,
               "message": "✓ No 'image:' fields found in compose file"}
        yield {"tool": "trivy-image", "type": "done", "file": display_name,
               "message": "■ Image scan skipped — no images to scan", "count": 0}
        return

    yield {"tool": "trivy-image", "type": "info", "file": display_name,
           "message": f"  Found {len(images)} image(s) in compose: {', '.join(images)}"}

    total = 0
    for img in images:
        async for ev in _scan_one_image(img, display_name, "compose image"):
            if ev.get("type") == "image_done":
                total += ev.get("count", 0)
                yield ev  # for compose, show per-image so user sees progress
                continue
            yield ev

    yield {"tool": "trivy-image", "type": "done", "file": display_name,
           "message": f"■ Compose image scan complete — {total} CVE(s) across {len(images)} image(s)",
           "count": total}


# scanarea de secrete (Trivy + verificarea proprie cu regex si entropie)

# formate uzuale de chei de serviciu; fiecare intrare: (regex, id_regula, titlu, severitate)
SECRET_PATTERNS = [
    # AWS
    (re.compile(r"AKIA[0-9A-Z]{16}"),
     "aws-access-key-id", "AWS Access Key ID", "critical"),
    (re.compile(r"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})"),
     "aws-secret-access-key", "AWS Secret Access Key", "critical"),
    # GitHub
    (re.compile(r"ghp_[A-Za-z0-9]{36}"),
     "github-pat", "GitHub Personal Access Token", "critical"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{82}"),
     "github-fine-grained-pat", "GitHub Fine-Grained PAT", "critical"),
    (re.compile(r"ghs_[A-Za-z0-9]{36}"),
     "github-oauth", "GitHub OAuth Token", "critical"),
    # GitLab
    (re.compile(r"glpat-[A-Za-z0-9_-]{20}"),
     "gitlab-pat", "GitLab Personal Access Token", "critical"),
    # Slack
    (re.compile(r"xox[abprs]-[A-Za-z0-9-]+"),
     "slack-token", "Slack Token", "high"),
    # Stripe
    (re.compile(r"sk_live_[A-Za-z0-9]{24,}"),
     "stripe-secret-key", "Stripe Live Secret Key", "critical"),
    # Google
    (re.compile(r"AIza[0-9A-Za-z_-]{35}"),
     "google-api-key", "Google API Key", "critical"),
    # JWT
    (re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
     "jwt-token", "JWT Token", "high"),
    # SendGrid
    (re.compile(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"),
     "sendgrid-key", "SendGrid API Key", "high"),
    # DigitalOcean
    (re.compile(r"dop_v1_[a-f0-9]{64}"),
     "digitalocean-pat", "DigitalOcean Personal Access Token", "critical"),
    # npm
    (re.compile(r"npm_[A-Za-z0-9]{36}"),
     "npm-token", "npm Access Token", "critical"),
    # Heroku
    (re.compile(r"(?i)heroku[a-z_-]*\s*[=:]\s*['\"]?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
     "heroku-api-key", "Heroku API Key", "high"),
    # Generic — ENV/ARG with a sensitive variable name
    (re.compile(
        r"(?im)^\s*(?:ENV|ARG)\s+[A-Z0-9_]*"
        r"(?:PASSWORD|PASSWD|PWD|SECRET|API[_-]?KEY|PRIVATE[_-]?KEY|TOKEN|"
        r"BEARER|CLIENT[_-]?SECRET|SIGNING[_-]?KEY|ACCESS[_-]?KEY|"
        r"CREDENTIAL|AUTH)[A-Z0-9_]*\s*[= ]\s*['\"]?([^\s'\"#]{8,})"
     ), "dockerfile-secret-env", "Hardcoded secret in ENV/ARG (sensitive name)", "high"),
    # Generic — same idea, but YAML/compose-style
    (re.compile(
        r"(?im)^\s*-?\s*[A-Z0-9_]*"
        r"(?:PASSWORD|PASSWD|PWD|SECRET|API[_-]?KEY|PRIVATE[_-]?KEY|TOKEN|"
        r"BEARER|CLIENT[_-]?SECRET|SIGNING[_-]?KEY|ACCESS[_-]?KEY|"
        r"CREDENTIAL|AUTH)[A-Z0-9_]*\s*[:=]\s*['\"]?([^\s'\"#$\{][^\s'\"#]{7,})"
     ), "yaml-secret-env", "Hardcoded secret in YAML environment", "high"),
    # PEM private keys
    (re.compile(r"-----BEGIN (?:RSA |OPENSSH |DSA |EC |PGP )?PRIVATE KEY-----"),
     "private-key", "Private Key", "critical"),
]


# verificarea pe entropie prinde valori care par aleatoare chiar cand numele
# variabilei nu se potriveste cu lista de cuvinte din SECRET_PATTERNS
# 4.5 biti/caracter inseamna cam base64 aleator; cuvintele englezesti stau pe la 3,
# numerele de versiune pe la 2.5; orice >= 4.5 e aproape sigur un token opac
_ENTROPY_THRESHOLD  = 4.5
_ENTROPY_MIN_LENGTH = 20      # prea scurt ca sa fie un secret real, il sar
# lucruri care par aleatoare dar au forma cunoscuta, pe astea nu le semnalez:
#   digesturi sha256, hash-uri de commit git, cai de fisiere, URL-uri
_ENTROPY_EXCLUDE = re.compile(
    r"^(?:sha\d+:[a-f0-9]+|[a-f0-9]{7,40}$|/[\w./\-]+|https?://)",
    re.IGNORECASE,
)
# prinde linii ENV/ARG/YAML: (nume_variabila, valoare); clasele de caractere
# de la final exclud referintele de variabila de shell de la inceputul valorii,
# ca `ENV FOO=$BAR` sa nu fie verificat
_ENV_VALUE_PATTERN = re.compile(
    r"(?im)^\s*(?:ENV\s+|ARG\s+|-\s*)?"
    r"([A-Z][A-Z0-9_]*)\s*"
    r"[:= ]\s*"
    r"['\"]?([^\s'\"#${}][^\s'\"#]+)"
)


def _shannon_entropy(s: str) -> float:
    # entropia Shannon in biti/caracter; pragul e in _ENTROPY_THRESHOLD
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _redact(s: str) -> str:
    # arat destul context cat sa gaseasca linia, dar nu afisez niciodata
    # secretul intreg, nici macar celui care l-a incarcat
    if len(s) > 20:
        return s[:8] + "****" + s[-4:]
    return s[:4] + "****"


def _scan_entropy(content: str) -> list[dict]:
    # semnalez valori ENV/ARG/YAML care par aleatoare, indiferent de numele variabilei
    findings = []
    for m in _ENV_VALUE_PATTERN.finditer(content):
        var_name, value = m.group(1), m.group(2)
        if len(value) < _ENTROPY_MIN_LENGTH:
            continue
        if _ENTROPY_EXCLUDE.match(value):
            continue
        if _shannon_entropy(value) < _ENTROPY_THRESHOLD:
            continue
        line_no = content[:m.start()].count("\n") + 1
        findings.append({
            "rule_id": "high-entropy-value",
            "title":   f"High-entropy value in {var_name}",
            "severity": "medium",
            "line":     line_no,
            "match":    _redact(value),
            # potrivire generica; o suprim daca o regula specifica prinde pe aceeasi linie
            "is_generic": True,
        })
    return findings


def _scan_with_regex(file_path: str) -> list[dict]:
    # scanerul propriu de secrete cu regex, prinde ce rateaza Trivy
    try:
        with open(file_path, "r", errors="replace") as f:
            content = f.read()
    except Exception:
        return []

    raw: list[dict] = []
    for pattern, rule_id, title, severity in SECRET_PATTERNS:
        for m in pattern.finditer(content):
            line_no = content[:m.start()].count("\n") + 1
            raw.append({
                "rule_id":  rule_id,
                "title":    title,
                "severity": severity,
                "line":     line_no,
                "match":    _redact(m.group(0)),
                "is_generic": rule_id in ("dockerfile-secret-env", "yaml-secret-env"),
            })

    raw.extend(_scan_entropy(content))

    # prima trecere de eliminare a duplicatelor: suprim potrivirile generice cand
    # o regula specifica a prins deja pe aceeasi linie; de exemplu o cheie AWS
    # declanseaza si `aws-access-key-id` (specifica) si `dockerfile-secret-env`
    # (generica), iar eu o vreau doar pe cea specifica
    specific_lines = {f["line"] for f in raw if not f["is_generic"]}
    deduped = [f for f in raw
               if not (f["is_generic"] and f["line"] in specific_lines)]

    # a doua trecere: comasez perechile (linie, regula) duplicate; un regex poate
    # prinde de doua ori pe o linie daca acopera ambele jumatati ale unui key=value
    seen, unique = set(), []
    for f in deduped:
        key = (f["line"], f["rule_id"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    return unique


async def stream_trivy_secret(file_path: str, display_name: str) -> AsyncGenerator[dict, None]:
    # scanarea de secrete Trivy + verificarea proprie cu regex si entropie
    yield {"tool": "trivy-secret", "type": "start", "file": display_name,
           "message": f"▶ [trivy-secret] Scanning {display_name} for secrets..."}

    # Trivy 0.70 ignora fisierele fara extensie ca 'Dockerfile' cand e apelat
    # prin `trivy fs`; solutia e o legatura simbolica spre un nume cu extensie
    # recunoscuta, ca Trivy sa-l scaneze; sterg legatura la final
    scan_path = file_path
    symlink = None
    base = os.path.basename(file_path).lower()
    if not base.endswith((".dockerfile", ".env", ".yml", ".yaml", ".tf", ".json", ".py")):
        symlink = file_path + ".dockerfile"
        try:
            if not os.path.exists(symlink):
                os.symlink(file_path, symlink)
            scan_path = symlink
        except Exception:
            # crearea legaturii a esuat (sistem read-only etc.), asa ca raman
            # pe calea originala; verificarea proprie cu regex tot ruleaza
            scan_path = file_path

    stdout, _, _ = await _run(
        ["trivy", "fs", "--scanners", "secret", "--format", "json",
         "--quiet", scan_path],
        timeout=60,
    )

    seen_keys: set[tuple] = set()
    count = 0

    # rezultatele Trivy
    if stdout:
        try:
            data = json.loads(stdout.decode())
            for result in data.get("Results", []):
                for secret in (result.get("Secrets") or []):
                    sev = secret.get("Severity", "HIGH")
                    rule = secret.get("RuleID", "")
                    line = secret.get("StartLine", 0)
                    match = secret.get("Match", "")
                    if len(match) > 20:
                        match = match[:10] + "****" + match[-6:]
                    key = (line, rule)
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)
                    count += 1
                    yield {
                        "tool": "trivy-secret", "type": "issue", "file": display_name,
                        "level": sev.lower(), "code": rule, "line": line,
                        "message": f"[{sev}] [Line {line}] {secret.get('Title','')}: {match}",
                    }
        except json.JSONDecodeError:
            pass

    # verificarea proprie cu regex, prinde ce a ratat Trivy
    for f in _scan_with_regex(file_path):
        key = (f["line"], f["rule_id"])
        if key in seen_keys:
            continue
        seen_keys.add(key)
        count += 1
        sev = f["severity"]
        yield {
            "tool": "trivy-secret", "type": "issue", "file": display_name,
            "level": sev, "code": f["rule_id"], "line": f["line"],
            "message": f"[{sev.upper()}] [Line {f['line']}] {f['title']}: {f['match']}",
        }

    if symlink:
        try: os.unlink(symlink)
        except Exception: pass

    if count == 0:
        yield {"tool": "trivy-secret", "type": "info", "file": display_name,
               "message": "✓ No hardcoded secrets detected"}
    yield {"tool": "trivy-secret", "type": "done", "file": display_name,
           "message": f"■ Secret scan complete — {count} secret(s) found", "count": count}


# orchestratorul pentru un fisier

async def _run_step(
    step: AsyncGenerator[dict, None], per_tool: dict, tally_key: str,
) -> AsyncGenerator[dict, None]:
    # trec mai departe evenimentele unui scaner si retin numarul final sub tally_key
    async for event in step:
        if event.get("type") == "done":
            per_tool[tally_key] = event.get("count", 0)
        yield event


async def scan_one_file(
    file_path: str, display_name: str, scanners: dict | None = None,
) -> AsyncGenerator[dict, None]:
    # aleg pipeline-ul dupa tipul fisierului si il rulez; se termina cu un file_summary
    kind = classify_file(display_name)
    s = scanners or {}

    yield {"tool": "system", "type": "file_start", "file": display_name, "kind": kind,
           "message": f"━━━ Scanning {display_name} ({kind}) ━━━"}

    per_tool: dict[str, int] = {}

    if kind not in ("dockerfile", "compose"):
        yield {"tool": "system", "type": "warning", "file": display_name,
               "message": f"⚠ Skipping {display_name} — unrecognized file type"}
        yield {"tool": "system", "type": "file_summary",
               "file": display_name, "kind": kind,
               "tools": per_tool, "total": 0,
               "message": f"── {display_name}: 0 issue(s)"}
        return

    # ambele pipeline-uri citesc continutul fisierului (FROM, RUN, parcurgere YAML)
    with open(file_path, "r") as fh:
        content = fh.read()

    # (toggle_key, tally_key, factory); factory amana crearea generatorului
    # pana stiu ca scanerul e activat
    if kind == "dockerfile":
        pipeline = [
            ("hadolint",     "hadolint",     lambda: stream_hadolint(file_path, display_name)),
            ("trivy_config", "trivy",        lambda: stream_trivy_config(file_path, display_name)),
            ("trivy_secret", "trivy-secret", lambda: stream_trivy_secret(file_path, display_name)),
            ("trivy_image",  "trivy-image",  lambda: stream_trivy_image(content, display_name)),
            ("package",      "package",      lambda: scan_packages(
                parse_packages_from_dockerfile(content), display_name, content)),
            ("cis",          "cis",          lambda: stream_cis_advisor(content, display_name)),
        ]
    else:  # compose
        pipeline = [
            ("trivy_config", "trivy",            lambda: stream_trivy_config(file_path, display_name)),
            ("trivy_secret", "trivy-secret",     lambda: stream_trivy_secret(file_path, display_name)),
            ("trivy_image",  "trivy-image",      lambda: stream_trivy_compose_images(content, display_name)),
            # analizorul CIS Cap. 5 e controlat de acelasi comutator `cis` ca si Cap. 4
            ("cis",          "compose-advisor",  lambda: stream_compose_advisor(content, display_name)),
        ]

    for toggle, tally, factory in pipeline:
        if s.get(toggle, True):
            async for event in _run_step(factory(), per_tool, tally):
                yield event

    yield {
        "tool": "system", "type": "file_summary",
        "file": display_name, "kind": kind,
        "tools": per_tool, "total": sum(per_tool.values()),
        "message": f"── {display_name}: {sum(per_tool.values())} issue(s)",
    }


# orchestratorul pentru mai multe fisiere

# leg cheile detaliate de numarare pe cele patru categorii care intereseaza
# panoul de scor; tot ce incepe cu "trivy" se aduna la "trivy", iar analizorul
# de compose intra la "cis" fiindca implementeaza CIS Cap. 5
def _bucket(tally_key: str) -> str:
    if tally_key.startswith("trivy"):
        return "trivy"
    if tally_key == "compose-advisor":
        return "cis"
    return tally_key


async def run_all_scanners_multi(
    files: list[dict], scanners: dict | None = None,
) -> AsyncGenerator[dict, None]:
    # trec fiecare fisier incarcat prin scan_one_file si adun totalurile
    per_file_summaries = []
    totals = {"hadolint": 0, "trivy": 0, "package": 0, "cis": 0}

    for f in files:
        async for event in scan_one_file(f["path"], f["name"], scanners):
            if event.get("type") == "file_summary":
                per_file_summaries.append({
                    "file":  event["file"],
                    "kind":  event["kind"],
                    "tools": event["tools"],
                    "total": event["total"],
                })
                for key, count in event["tools"].items():
                    bucket = _bucket(key)
                    totals[bucket] = totals.get(bucket, 0) + count
            yield event

    grand = sum(totals.values())

    # un banner frumos in consola live
    yield {"tool": "system", "type": "summary_divider", "message": "═" * 56}
    yield {"tool": "system", "type": "summary_header",  "message": "  SCAN SUMMARY"}
    yield {"tool": "system", "type": "summary_divider", "message": "═" * 56}
    for pfs in per_file_summaries:
        yield {"tool": "system", "type": "summary_file",
               "message": f"  {pfs['file']}  [{pfs['kind']}]  →  {pfs['total']} issue(s)"}
        for tool, count in pfs["tools"].items():
            yield {"tool": "system", "type": "summary_item",
                   "message": f"      • {tool}: {count}"}
    yield {"tool": "system", "type": "summary_divider", "message": "─" * 56}
    yield {"tool": "system", "type": "summary_total",
           "message": f"  TOTAL: {grand} finding(s) across {len(per_file_summaries)} file(s)"}
    yield {"tool": "system", "type": "summary_divider", "message": "═" * 56}

    # sumarul structurat pe care il citeste panoul de scor din frontend
    yield {
        "tool":     "system",
        "type":     "summary",
        "message":  f"━━ Scan complete ━━  {grand} total finding(s)",
        "hadolint": totals["hadolint"],
        "trivy":    totals["trivy"],
        "package":  totals["package"],
        "cis":      totals["cis"],
        "files":    per_file_summaries,
        "total":    grand,
    }
