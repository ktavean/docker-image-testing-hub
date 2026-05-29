# remedierea automata a fisierelor Dockerfile
# fiecare reparatie e o functie (continut) -> (continut_nou, [mesaje])
# folosesc dockerfile-parse pentru structura si bashlex pentru shell,
# fara regex peste structura Dockerfile-ului
import difflib
import io
import re
from typing import List, Tuple

import bashlex
from dockerfile_parse import DockerfileParser


# ajutoare pentru structura si editarea pe linii

def _parse(content: str) -> list:
    # [{instruction, startline, endline, value}, ...]
    return DockerfileParser(fileobj=io.BytesIO(content.encode())).structure


def _edit_lines(lines: List[str], edits: dict[int, str]) -> List[str]:
    # edits: {numar_linie_de_la_0: linia_noua}
    out = list(lines)
    for ln, new in edits.items():
        out[ln] = new
    return out


def _insert_before(lines: List[str], target: int, new_lines: List[str]) -> List[str]:
    return lines[:target] + new_lines + lines[target:]


def _bash_has_pipe(run_value: str) -> bool:
    # parcurg arborele bashlex ca sa vad daca exista chiar un operator de pipe
    def visit(node) -> bool:
        if node.kind == "pipe":
            return True
        for child in getattr(node, "parts", []) + getattr(node, "list", []):
            if visit(child):
                return True
        return False
    try:
        return any(visit(n) for n in bashlex.parse(run_value))
    except Exception:
        # bashlex se poate impotmoli la heredoc-uri / subshell-uri ciudate
        return " | " in run_value


def _last_runtime_line(instructions: list, total_lines: int) -> int:
    # indexul liniei ultimului CMD/ENTRYPOINT (sau sfarsitul fisierului)
    last = total_lines
    for instr in instructions:
        if instr["instruction"] in ("CMD", "ENTRYPOINT"):
            last = instr["startline"]
    return last


# reparatiile; fiecare intoarce (continut_nou, mesaje_aplicate)

def fix_add_to_copy(content: str) -> Tuple[str, List[str]]:
    # DL3020, inlocuiesc ADD cu COPY cand nu aduce un URL sau o arhiva
    lines = content.splitlines(keepends=True)
    edits: dict[int, str] = {}
    applied: List[str] = []

    for instr in _parse(content):
        if instr["instruction"] != "ADD":
            continue
        parts = instr["value"].split()
        src = parts[0] if parts else ""

        is_archive = any(src.lower().endswith(ext)
                         for ext in (".tar", ".gz", ".tgz", ".zip", ".bz2", ".xz"))
        is_url = src.startswith(("http://", "https://"))
        if is_archive or is_url:
            continue

        for ln in range(instr["startline"], instr["endline"] + 1):
            original = lines[ln]
            fixed = original.replace("ADD ", "COPY ", 1)
            if fixed != original:
                edits[ln] = fixed
        applied.append(f"DL3020: Replaced ADD with COPY (src: {src!r})")

    return "".join(_edit_lines(lines, edits)), applied


def fix_shell_pipefail(content: str) -> Tuple[str, List[str]]:
    # DL4006, pun `set -o pipefail` inaintea liniilor RUN care folosesc pipe
    lines = content.splitlines(keepends=True)
    edits: dict[int, str] = {}
    applied: List[str] = []

    for instr in _parse(content):
        if instr["instruction"] != "RUN":
            continue
        value = instr["value"]
        if "pipefail" in value or not _bash_has_pipe(value):
            continue

        ln = instr["startline"]
        edits[ln] = lines[ln].replace("RUN ", "RUN set -o pipefail && ", 1)
        applied.append(f"DL4006: Added pipefail to RUN with pipe (line {ln + 1})")

    return "".join(_edit_lines(lines, edits)), applied


def fix_apt_get_cleanup(content: str) -> Tuple[str, List[str]]:
    # DL3009, adaug `rm -rf /var/lib/apt/lists/*` la RUN-urile cu apt-get install
    lines = content.splitlines(keepends=True)
    applied: List[str] = []
    # cand inserez linii noi, tot ce e dedesubt se deplaseaza; tin minte decalajul
    offset = 0

    for instr in _parse(content):
        if instr["instruction"] != "RUN":
            continue
        val = instr["value"]
        if "apt-get install" not in val or "rm -rf /var/lib/apt/lists" in val:
            continue

        end_ln = instr["endline"] + offset
        original = lines[end_ln]
        stripped = original.rstrip("\n")
        if stripped.endswith("\\"):
            # RUN-ul era deja pe mai multe linii, asa ca adaug inca o continuare
            cleanup = "    && rm -rf /var/lib/apt/lists/*\n"
            lines = lines[:end_ln + 1] + [cleanup] + lines[end_ln + 1:]
            offset += 1
        else:
            lines[end_ln] = stripped + " \\\n    && rm -rf /var/lib/apt/lists/*\n"
        applied.append(f"DL3009: Added apt-get cleanup (line {instr['endline'] + 1})")

    return "".join(lines), applied


def fix_root_user(content: str) -> Tuple[str, List[str]]:
    # DL3002, daca nu exista un USER non-root, adaug unul inainte de CMD/ENTRYPOINT
    instrs = _parse(content)
    lines = content.splitlines(keepends=True)

    for instr in instrs:
        if instr["instruction"] == "USER":
            if instr["value"].strip().lower() not in ("root", "0"):
                return content, []   # already non-root

    insert_at = _last_runtime_line(instrs, len(lines))
    new_lines = [
        "\n",
        "# Security: run as non-root user\n",
        "RUN groupadd --gid 1001 appgroup \\\n",
        "    && useradd --uid 1001 --gid appgroup --shell /bin/sh --create-home appuser\n",
        "USER appuser\n",
    ]
    return "".join(_insert_before(lines, insert_at, new_lines)), \
           ["DL3002: Added non-root USER appuser (uid=1001)"]


def fix_latest_tag(content: str) -> Tuple[str, List[str]]:
    # DL3007, las o nota deasupra liniilor FROM fara versiune fixata
    lines = content.splitlines(keepends=True)
    applied: List[str] = []
    offset = 0

    for instr in _parse(content):
        if instr["instruction"] != "FROM":
            continue
        image = instr["value"].split()[0]
        if "@" in image:
            continue  # digest-pinned, fine
        tag = image.split(":")[-1] if ":" in image else "latest"
        if tag.lower() != "latest":
            continue

        ln = instr["startline"] + offset
        base_name = image.split(":")[0]
        reminder = [
            "# TODO(hardening): pin base image to a specific version or digest\n",
            f"# Example: {base_name}:22.04  or  {base_name}@sha256:<digest>\n",
        ]
        lines = lines[:ln] + reminder + lines[ln:]
        offset += len(reminder)
        applied.append(f"DL3007: Added pin-version reminder for {image!r}")

    return "".join(lines), applied


def fix_no_healthcheck(content: str) -> Tuple[str, List[str]]:
    # CKV_DOCKER_7, adaug un HEALTHCHECK sablon daca lipseste
    instrs = _parse(content)
    if any(i["instruction"] == "HEALTHCHECK" for i in instrs):
        return content, []

    lines = content.splitlines(keepends=True)
    insert_at = _last_runtime_line(instrs, len(lines))
    new_lines = [
        "\n",
        "# Security: add a HEALTHCHECK (customise for your service)\n",
        "HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \\\n",
        "    CMD curl -f http://localhost/ || exit 1\n",
    ]
    return "".join(_insert_before(lines, insert_at, new_lines)), \
           ["CKV_DOCKER_7: Added HEALTHCHECK instruction"]


# tiparele pe care le marcheaza reparatia de avertizare a secretelor
# (un subset din cele ale scanerului, doar cele de incredere mai mare,
# fiindca modificam fisierul)
_SECRET_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"),                          "AWS Access Key ID"),
    (re.compile(r"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}"),
     "AWS Secret Access Key"),
    (re.compile(r"ghp_[A-Za-z0-9]{36}"),                       "GitHub Personal Access Token"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{82}"),               "GitHub Fine-Grained PAT"),
    (re.compile(r"ghs_[A-Za-z0-9]{36}"),                       "GitHub OAuth Token"),
    (re.compile(r"glpat-[A-Za-z0-9_-]{20}"),                   "GitLab PAT"),
    (re.compile(r"AIza[0-9A-Za-z_-]{35}"),                     "Google API Key"),
    (re.compile(r"sk_live_[A-Za-z0-9]{24,}"),                  "Stripe Live Secret Key"),
    (re.compile(r"xox[abprs]-[A-Za-z0-9-]+"),                  "Slack Token"),
    (re.compile(r"npm_[A-Za-z0-9]{36}"),                       "npm Access Token"),
    (re.compile(r"-----BEGIN (?:RSA |OPENSSH |DSA |EC |PGP )?PRIVATE KEY-----"),
     "PEM Private Key"),
    (re.compile(
        r"(?im)^\s*(?:ENV|ARG)\s+[A-Z0-9_]*"
        r"(?:PASSWORD|PASSWD|PWD|SECRET|API[_-]?KEY|PRIVATE[_-]?KEY|TOKEN|"
        r"BEARER|CLIENT[_-]?SECRET|SIGNING[_-]?KEY|ACCESS[_-]?KEY|"
        r"CREDENTIAL|AUTH)[A-Z0-9_]*\s*[= ]\s*['\"]?[^\s'\"#]{8,}"
     ), "Hardcoded credential in ENV/ARG"),
]


def fix_secret_warnings(content: str) -> Tuple[str, List[str]]:
    # pun un comentariu de avertizare deasupra fiecarei linii cu secret
    # nu pot inlocui automat secretele (nu stiu valorile reale), dar marcandu-le
    # in fisier ma asigur ca nu sunt ratate la revizuire
    lines = content.splitlines(keepends=True)
    flagged: dict[int, set[str]] = {}
    for pattern, label in _SECRET_PATTERNS:
        for ln_no, line in enumerate(lines):
            if pattern.search(line):
                flagged.setdefault(ln_no, set()).add(label)

    if not flagged:
        return content, []

    applied: List[str] = []
    # merg de jos in sus, ca insertiile sa nu deplaseze indicii de mai jos
    out = list(lines)
    for ln_no in sorted(flagged.keys(), reverse=True):
        prev = out[ln_no - 1] if ln_no > 0 else ""
        if "WARNING (DHH):" in prev:
            continue   # deja marcat, nu pun de doua ori
        labels = " / ".join(sorted(flagged[ln_no]))
        warning = [
            f"# WARNING (DHH): {labels} detected — replace with build-time arg or secret manager\n",
            "# See: https://docs.docker.com/build/building/secrets/\n",
        ]
        out = out[:ln_no] + warning + out[ln_no:]
        applied.append(f"Inserted secret warning at line {ln_no + 1}: {', '.join(sorted(flagged[ln_no]))}")

    return "".join(out), applied


FIXERS = [
    {
        "id": "dl3020_add_to_copy",
        "rule": "DL3020",
        "description": "Replace ADD with COPY — ADD can silently fetch URLs and extract archives",
        "confidence": "HIGH",
        "fn": fix_add_to_copy,
    },
    {
        "id": "dl4006_pipefail",
        "rule": "DL4006",
        "description": "Add set -o pipefail to RUN commands with pipes (detected via bashlex AST)",
        "confidence": "HIGH",
        "fn": fix_shell_pipefail,
    },
    {
        "id": "dl3009_apt_cleanup",
        "rule": "DL3009",
        "description": "Append apt-get list cleanup to reduce attack surface and image size",
        "confidence": "MEDIUM",
        "fn": fix_apt_get_cleanup,
    },
    {
        "id": "dl3002_root_user",
        "rule": "DL3002",
        "description": "Add non-root user and switch to it before CMD/ENTRYPOINT",
        "confidence": "MEDIUM",
        "fn": fix_root_user,
    },
    {
        "id": "dl3007_latest_tag",
        "rule": "DL3007",
        "description": "Add comment reminding to pin base image tag (FROM uses unpinned tag)",
        "confidence": "LOW",
        "fn": fix_latest_tag,
    },
    {
        "id": "ckv_docker7_healthcheck",
        "rule": "CKV_DOCKER_7",
        "description": "Add HEALTHCHECK instruction template (customise CMD for your service)",
        "confidence": "LOW",
        "fn": fix_no_healthcheck,
    },
    {
        "id": "secret_warnings",
        "rule": "SECRET",
        "description": "Insert WARNING comments above hardcoded secrets (cannot auto-replace; values unknown)",
        "confidence": "HIGH",
        "fn": fix_secret_warnings,
    },
]

_FIXER_MAP = {f["id"]: f for f in FIXERS}


# interfata publica

def _diff(original: str, fixed: str, filename: str) -> str:
    return "".join(difflib.unified_diff(
        original.splitlines(keepends=True),
        fixed.splitlines(keepends=True),
        fromfile=f"a/{filename}",
        tofile=f"b/{filename}",
    ))


def preview_fixes(content: str, filename: str = "Dockerfile") -> list:
    # intorc reparatiile propuse fara sa modific nimic
    results = []
    for fixer in FIXERS:
        try:
            new, applied = fixer["fn"](content)
        except Exception:
            continue  # daca o reparatie pica, nu opresc toata previzualizarea
        if applied:
            results.append({
                "fix_id":      fixer["id"],
                "rule":        fixer["rule"],
                "description": fixer["description"],
                "confidence":  fixer["confidence"],
                "changes":     applied,
                "diff":        _diff(content, new, filename),
            })
    return results


def apply_fixes(content: str, fix_ids: List[str]) -> Tuple[str, List[str]]:
    # aplic in ordine reparatiile cerute; sar peste cele necunoscute sau care esueaza
    current = content
    all_applied: List[str] = []
    for fix_id in fix_ids:
        fixer = _FIXER_MAP.get(fix_id)
        if not fixer:
            continue
        try:
            current, applied = fixer["fn"](current)
            all_applied.extend(applied)
        except Exception:
            pass
    return current, all_applied
