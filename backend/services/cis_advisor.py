# CIS Docker Benchmark v1.8.0, Capitolul 4 (configurarea fisierului de build)
# parcurg arborele Dockerfile (dockerfile-parse) si comenzile shell din RUN
# (bashlex) ca sa gasesc probleme pe care Hadolint si Trivy nu le acopera
# implementez regulile: 4.2, 4.3, 4.4, 4.5, 4.8, 4.11, 4.12
# 4.1/4.6/4.7/4.9/4.10 le trateaza Hadolint sau scanerul de secrete
import io
import logging
import re
from dataclasses import dataclass
from typing import AsyncGenerator

from services.pkg_parser import walk_commands

try:
    import bashlex
except ImportError:
    bashlex = None

try:
    from dockerfile_parse import DockerfileParser
except ImportError:
    DockerfileParser = None

logger = logging.getLogger("cis_advisor")


@dataclass
class Finding:
    rule:        str
    title:       str
    severity:    str           # critical | high | medium | low
    line:        int
    description: str
    suggestion:  str
    snippet:     str = ""


# imagine de baza grea -> varianta slim/distroless recomandata (CIS 4.3)
BLOATED_BASES = {
    "ubuntu":     "ubuntu:24.04 (or python:3.12-slim, node:22-alpine, etc.)",
    "debian":     "debian:12-slim or a language-specific slim image",
    "centos":     "rockylinux:9-minimal or alpine:3",
    "fedora":     "fedora-minimal or alpine:3",
    "rockylinux": "rockylinux:9-minimal",
    "almalinux":  "almalinux:9-minimal",
}

# lucruri care aproape niciodata n-au ce cauta intr-o imagine de productie (CIS 4.3)
UNNECESSARY_PACKAGES = {
    "wget", "curl", "vim", "vim-tiny", "nano", "emacs", "telnet", "netcat",
    "netcat-openbsd", "nmap", "tcpdump", "traceroute", "iputils-ping",
    "net-tools", "dnsutils", "iproute2", "ssh", "openssh-server",
    "openssh-client", "git", "subversion", "mercurial", "build-essential",
    "gcc", "g++", "make", "perl", "ruby", "tar", "unzip", "zip",
}

# registrele pe care le consider de incredere implicit (CIS 4.2)
TRUSTED_REGISTRY_PREFIXES = (
    "docker.io/", "registry.access.redhat.com/", "registry.redhat.io/",
    "quay.io/", "gcr.io/", "k8s.gcr.io/", "registry.k8s.io/",
    "ghcr.io/", "mcr.microsoft.com/", "public.ecr.aws/",
)


def _parse_shell(run_value: str) -> list[list[str]]:
    # sparg o valoare RUN in liste de cuvinte; daca nu merge, impart dupa spatii
    if not bashlex:
        return [[w for w in re.split(r"\s+", run_value) if w]]
    # bashlex se incurca la specificatii ca '>=~1.0', asa ca scot tildele intai
    sanitized = re.sub(r"([=<>~])~", r"\1TILDE", run_value)
    try:
        nodes = bashlex.parse(sanitized)
    except Exception:
        return [[w for w in re.split(r"\s+", run_value) if w]]
    commands = []
    for node in nodes:
        for words in walk_commands(node):
            commands.append([w.replace("TILDE", "~") for w in words])
    return commands


def _strip_alias(value: str) -> str:
    # din FROM 'imagine AS stadiu' scot doar 'imagine'
    return value.strip().split(" AS ")[0].split(" as ")[0].strip()


def _final_from_index(instructions) -> int | None:
    # indexul ultimului FROM, adica stadiul care chiar ajunge in imagine
    # la build multi-stadiu doar ultimul stadiu devine imaginea finala,
    # cele de constructie se arunca; regulile pe imaginea de baza (4.2, 4.3, 4.5)
    # trebuie sa judece doar stadiul final, fiindca unul de constructie poate
    # folosi o distributie completa si nimeni nu fixeaza prin digest un stadiu
    # de aruncat; intorc None daca nu exista niciun FROM
    last = None
    for i, instr in enumerate(instructions):
        if instr["instruction"] == "FROM":
            last = i
    return last


def _final_stage_run_range(instructions) -> tuple[int, int]:
    # intervalul [start, end) de indici care acopera corpul stadiului final,
    # adica de la ultimul FROM pana la sfarsitul fisierului
    # il folosesc ca sa limitez verificarile pe RUN la stadiul care ajunge in imagine
    idx = _final_from_index(instructions)
    if idx is None:
        return (0, 0)
    return (idx, len(instructions))


_SHELL_OPERATORS = frozenset({"&&", "||", ";", "|", "&"})


def _install_pkg_args(words: list[str], install_idx: int) -> list[str]:
    # numele pachetelor dintr-o comanda de install: tot ce e dupa cuvantul
    # install pana la primul operator de shell
    # bashlex nu imparte mereu lanturile cu && in comenzi separate, asa ca un
    # RUN gen `apt-get install -y curl && rm -rf ...` poate veni ca o singura
    # lista de cuvinte; daca nu ma opresc la operator, as intra in comanda
    # urmatoare si as crede ca `rm` sau calea sunt "pachete", de unde ieseau
    # alarme false CIS-4.3 / CIS-4.4
    args = []
    for w in words[install_idx + 1:]:
        if w in _SHELL_OPERATORS:
            break
        args.append(w)
    return args


# verificarile pe reguli

def _check_4_2_and_4_5(instructions, findings):
    # 4.2 baza de incredere + fixare prin tag, 4.5 fixare prin digest
    # judec doar FROM-ul din stadiul final; cele de constructie se arunca,
    # deci imaginea lor nici nu ajunge in productie, nici nu are nevoie de digest
    final_idx = _final_from_index(instructions)
    if final_idx is None:
        return
    for idx, instr in enumerate(instructions):
        if instr["instruction"] != "FROM" or idx != final_idx:
            continue
        line = instr["startline"] + 1
        image = _strip_alias(instr["value"])
        if image.lower() == "scratch":
            continue

        # fara tag inseamna implicit :latest
        if ":" not in image.split("/")[-1]:
            findings.append(Finding(
                rule="CIS-4.2", title="Untagged base image",
                severity="medium", line=line,
                description=(
                    f"Base image '{image}' has no tag. Docker will pull :latest, "
                    f"which is non-deterministic."
                ),
                suggestion="Pin to a specific version tag (e.g. python:3.12-slim) "
                           "or, ideally, an immutable digest.",
                snippet=f"FROM {image}:<specific-tag>",
            ))
            continue

        # :latest pus explicit
        if image.endswith(":latest") or ":latest@" in image:
            findings.append(Finding(
                rule="CIS-4.2", title="Base image uses :latest tag",
                severity="medium", line=line,
                description=f"Base image '{image}' uses :latest — same problem, non-deterministic builds.",
                suggestion="Pin to a specific version tag or a digest.",
                snippet=f"FROM {image.replace(':latest', ':<specific-tag>')}",
            ))

        # 4.5, lipseste digestul
        if "@sha256:" not in image:
            findings.append(Finding(
                rule="CIS-4.5", title="Base image not pinned by digest",
                severity="low", line=line,
                description=(
                    f"'{image}' is referenced by tag, not by SHA256 digest. "
                    f"Tags are mutable; same tag, different image, over time."
                ),
                suggestion="For supply-chain integrity, pin by digest. "
                           "Get it with 'docker inspect <image> --format=\"{{.Id}}\"'.",
                snippet=f"FROM {image}@sha256:<digest>",
            ))

        # registru neincrezut: semnalez doar daca exista o componenta de registru explicita
        if "/" in image:
            first = image.split("/")[0]
            looks_like_host = "." in first or ":" in first
            if looks_like_host and not any(image.startswith(p) for p in TRUSTED_REGISTRY_PREFIXES):
                findings.append(Finding(
                    rule="CIS-4.2", title="Base image from non-standard registry",
                    severity="medium", line=line,
                    description=f"Image pulled from '{first}' — not in our list of trusted registries.",
                    suggestion="Verify this registry is approved by your org. "
                               "Prefer official images, scan third-party ones first.",
                ))


def _check_4_3_unnecessary(instructions, findings):
    # 4.3, imagini de baza grele + pachete inutile
    # ma uit doar la stadiul final: unul de constructie poate folosi o
    # distributie completa si unelte de build, nimic din astea neajungand in imagine
    final_idx = _final_from_index(instructions)
    start, end = _final_stage_run_range(instructions)

    # imagine de baza grea, doar FROM-ul din stadiul final
    if final_idx is not None:
        instr = instructions[final_idx]
        image = _strip_alias(instr["value"])
        image_name = image.split("/")[-1].split(":")[0].split("@")[0].lower()
        if image_name in BLOATED_BASES:
            findings.append(Finding(
                rule="CIS-4.3", title="Bloated base image",
                severity="medium", line=instr["startline"] + 1,
                description=(
                    f"'{image_name}' is a full distro image, which carries packages "
                    f"you almost certainly don't need at runtime."
                ),
                suggestion=f"Consider a slim/minimal variant: {BLOATED_BASES[image_name]}.",
            ))

    # pachete inutile: ma uit doar la RUN-urile din stadiul final
    # un pachet folosit de comanda HEALTHCHECK nu e "inutil", asa ca strang
    # binarele alea si le sar (de exemplu curl folosit intr-un
    # `HEALTHCHECK CMD curl -f http://localhost/`)
    healthcheck_tools: set[str] = set()
    for instr in instructions:
        if instr["instruction"] != "HEALTHCHECK":
            continue
        for tok in re.findall(r"[A-Za-z0-9_.\-]+", instr["value"]):
            healthcheck_tools.add(tok.split("/")[-1])

    for instr in instructions[start:end]:
        if instr["instruction"] != "RUN":
            continue
        line = instr["startline"] + 1
        for words in _parse_shell(instr["value"]):
            if not words:
                continue
            binary = words[0].split("/")[-1]
            if binary not in ("apt-get", "apt", "apk", "yum", "dnf"):
                continue
            install_kw = "add" if binary == "apk" else "install"
            try:
                idx = words.index(install_kw)
            except ValueError:
                continue
            unneeded = []
            for w in _install_pkg_args(words, idx):
                if w.startswith("-"):
                    continue
                pkg = re.split(r"[=<>~]", w, maxsplit=1)[0]
                if pkg in UNNECESSARY_PACKAGES and pkg not in healthcheck_tools:
                    unneeded.append(pkg)
            if unneeded:
                findings.append(Finding(
                    rule="CIS-4.3", title="Potentially unnecessary packages",
                    severity="low", line=line,
                    description=(
                        f"Installing {', '.join(unneeded)} grows your attack surface. "
                        f"These tools are also handy for an attacker post-compromise."
                    ),
                    suggestion="Drop them if only build-time. Use multi-stage builds "
                               "so dev tools never reach the final image.",
                ))


def _check_4_4_version_pinning(instructions, findings):
    # 4.4, fixarea versiunilor de pachete pentru build-uri reproductibile
    # tot pe stadiul final (la fel ca 4.2/4.3, fiindca DHH puncteaza imaginea
    # care ajunge in productie); numele pachetelor le iau cu _install_pkg_args
    # ca un `&& rm ...` la coada sa nu fie luat drept pachet fara versiune
    start, end = _final_stage_run_range(instructions)
    for instr in instructions[start:end]:
        if instr["instruction"] != "RUN":
            continue
        line = instr["startline"] + 1
        for words in _parse_shell(instr["value"]):
            if not words or words[0].split("/")[-1] not in ("apt-get", "apt"):
                continue
            try:
                idx = words.index("install")
            except ValueError:
                continue
            unpinned = [
                w for w in _install_pkg_args(words, idx)
                if not w.startswith("-")
                and "=" not in w and w not in UNNECESSARY_PACKAGES
            ]
            if len(unpinned) >= 2:  # merita semnalat doar cand sunt mai multe
                preview = ", ".join(unpinned[:5]) + ("..." if len(unpinned) > 5 else "")
                findings.append(Finding(
                    rule="CIS-4.4", title="Unpinned package versions",
                    severity="low", line=line,
                    description=(
                        f"Packages installed without version pin: {preview}. "
                        f"Builds aren't reproducible — version is whatever's current "
                        f"at build time."
                    ),
                    suggestion="Pin them: 'apt-get install -y curl=7.88.1-10+deb12u5'. "
                               "Use 'apt-cache policy <pkg>' to find versions.",
                ))


def _check_4_8_setuid(instructions, findings):
    # 4.8, scot bitii setuid/setgid inainte de USER (Nivel 2)
    has_cleanup = any(
        instr["instruction"] == "RUN"
        and re.search(r"-perm\s+[/+-]?6000.*chmod\s+a-s", instr["value"], re.DOTALL)
        for instr in instructions
    )
    if has_cleanup:
        return

    # merita semnalat doar daca imaginea chiar ruleaza ceva
    if not any(i["instruction"] in ("RUN", "CMD", "ENTRYPOINT") for i in instructions):
        return

    # pun sugestia langa ultimul CMD/ENTRYPOINT, pentru context
    insert_line = 1
    for instr in instructions:
        if instr["instruction"] in ("CMD", "ENTRYPOINT"):
            insert_line = instr["startline"] + 1

    findings.append(Finding(
        rule="CIS-4.8", title="setuid/setgid permissions not stripped",
        severity="low", line=insert_line,
        description="The image doesn't strip setuid/setgid bits. If an attacker "
                    "gets code execution, those bits can be used for privilege escalation.",
        suggestion="Add a RUN step before USER that removes setuid/setgid from "
                   "binaries you don't need them on (test it — ping legitimately needs setuid).",
        snippet=r"RUN find / -perm /6000 -type f -exec chmod a-s {} \; || true",
    ))


def _check_4_11_verified(instructions, findings):
    # 4.11, nu accept pachete nesemnate si nu trec scripturi direct prin shell
    for instr in instructions:
        if instr["instruction"] != "RUN":
            continue
        line = instr["startline"] + 1
        value = instr["value"]

        if re.search(r"--allow-unauthenticated|--force-yes", value):
            findings.append(Finding(
                rule="CIS-4.11", title="Package authentication disabled",
                severity="high", line=line,
                description="--allow-unauthenticated / --force-yes turns off GPG verification. "
                            "A compromised mirror or MITM can drop in any package.",
                suggestion="Remove the flag. If a repo lacks signing, add its key properly "
                           "via /etc/apt/trusted.gpg.d/.",
            ))

        # curl ... | sh / wget ... | bash, anti-tiparul clasic de script de install
        # interpretorul trebuie sa fie un cuvant intreg: `\d*` permite python3/perl5,
        # iar lookahead-ul cere spatiu / sfarsit de linie / un metacaracter de shell
        # dupa el; fara asta, `sh` se potrivea in interiorul lui `sha256sum` si
        # semnala chiar tiparul verifica-apoi-ruleaza pe care regula il recomanda
        if re.search(
            r"(?:curl|wget)\s+[^|]*\|\s*"
            r"(?:bash|sh|zsh|ksh|dash|python|ruby|perl|node)\d*(?=$|\s|[;&|])",
            value,
        ):
            findings.append(Finding(
                rule="CIS-4.11", title="Piping remote script to interpreter",
                severity="high", line=line,
                description="Downloads a script and pipes it straight to an interpreter "
                            "with no checksum or signature check.",
                suggestion="Download to a file, verify its SHA256 against a known value, then run it.",
                snippet=(
                    "RUN curl -fsSL https://example.com/install.sh -o /tmp/install.sh && \\\n"
                    "    echo \"<expected-sha256>  /tmp/install.sh\" | sha256sum -c - && \\\n"
                    "    sh /tmp/install.sh && rm /tmp/install.sh"
                ),
            ))


# artefacte pe care ne asteptam sa le vedem verificate dupa descarcare
_DOWNLOAD_RE = re.compile(
    r"(?:curl|wget)\s+[^|;&]*?(\S+\.(?:tar\.gz|tgz|tar\.bz2|tar\.xz|zip|deb|rpm|jar|exe|bin))"
)
_VERIFY_RE = re.compile(r"(?:sha256sum|sha512sum|md5sum|gpg\s+--verify|cosign\s+verify)")


def _check_4_12_signed_artifacts(instructions, findings):
    # 4.12, verific artefactele descarcate
    for instr in instructions:
        if instr["instruction"] != "RUN":
            continue
        line = instr["startline"] + 1
        value = instr["value"]
        m = _DOWNLOAD_RE.search(value)
        if not m or _VERIFY_RE.search(value):
            continue
        findings.append(Finding(
            rule="CIS-4.12", title="Downloaded artifact not verified",
            severity="medium", line=line,
            description=f"'{m.group(1)}' is downloaded without verifying its checksum "
                        f"or signature.",
            suggestion="Add SHA256 verification right after download. "
                       "For OCI artifacts use cosign verify.",
            snippet=(
                "RUN curl -fsSL <url> -o /tmp/artifact && \\\n"
                "    echo \"<sha256>  /tmp/artifact\" | sha256sum -c - && \\\n"
                "    <use-artifact> && rm /tmp/artifact"
            ),
        ))


def analyze_dockerfile(content: str) -> list[Finding]:
    if not DockerfileParser:
        logger.warning("dockerfile-parse not available, skipping CIS analysis")
        return []
    try:
        dfp = DockerfileParser(fileobj=io.BytesIO(content.encode()))
        instructions = dfp.structure
    except Exception as exc:
        logger.warning("Failed to parse Dockerfile: %s", exc)
        return []

    findings: list[Finding] = []
    _check_4_2_and_4_5(instructions, findings)
    _check_4_3_unnecessary(instructions, findings)
    _check_4_4_version_pinning(instructions, findings)
    _check_4_8_setuid(instructions, findings)
    _check_4_11_verified(instructions, findings)
    _check_4_12_signed_artifacts(instructions, findings)
    logger.info("CIS Advisor: %d instructions, %d finding(s)", len(instructions), len(findings))
    return findings


async def stream_cis_advisor(content: str, display_name: str) -> AsyncGenerator[dict, None]:
    yield {"tool": "cis", "type": "start", "file": display_name,
           "message": "▶ [cis] CIS Docker Benchmark v1.8.0 — Chapter 4 advisor..."}

    findings = analyze_dockerfile(content)
    for f in findings:
        yield {
            "tool": "cis", "type": "issue", "file": display_name,
            "level": f.severity, "code": f.rule, "line": f.line,
            "message": f"[{f.rule}] [Line {f.line}] {f.title}: {f.description}",
            "suggestion": f.suggestion,
            "snippet": f.snippet,
        }

    if not findings:
        yield {"tool": "cis", "type": "info", "file": display_name,
               "message": "✓ No CIS Chapter 4 issues found"}
    yield {"tool": "cis", "type": "done", "file": display_name,
           "message": f"■ CIS advisor complete — {len(findings)} recommendation(s)",
           "count": len(findings)}
