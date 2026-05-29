# citesc instructiunile RUN ca sa vad ce pachete se instaleaza
# il folosesc si scanerul OSV (principal) si rezerva NVD
import io
import logging
import re

try:
    import bashlex
except ImportError:
    bashlex = None

try:
    from dockerfile_parse import DockerfileParser
except ImportError:
    DockerfileParser = None

logger = logging.getLogger("pkg_parser")

# pachete generice / de infrastructura care nu ne intereseaza la CVE
SKIP_PACKAGES = {
    "ca-certificates", "apt-transport-https", "gnupg", "gnupg2",
    "lsb-release", "software-properties-common", "dirmngr",
}

# binarul managerului de pachete -> (subcomanda de install, eticheta)
PKG_MANAGERS = {
    "apt-get": ("install", "apt"),
    "apt":     ("install", "apt"),
    "apk":     ("add",     "apk"),
    "yum":     ("install", "yum"),
    "dnf":     ("install", "dnf"),
    "pip":     ("install", "pip"),
    "pip3":    ("install", "pip"),
    "npm":     ("install", "npm"),
}

# manager -> ecosistem OSV; "apt" devine "Debian" sau "Ubuntu"
# in functie de imaginea din FROM
OSV_ECOSYSTEMS = {
    "apt":  "Debian",
    "apk":  "Alpine",
    "yum":  "Red Hat",
    "dnf":  "Red Hat",
    "pip":  "PyPI",
    "npm":  "npm",
}


def extract_words(node) -> list[str]:
    # scot toate cuvintele dintr-un nod din arborele bashlex
    words = []
    if hasattr(node, "word"):
        words.append(node.word)
    for child in getattr(node, "parts", []):
        words.extend(extract_words(child))
    if hasattr(node, "list"):
        for item in node.list:
            words.extend(extract_words(item))
    return words


def walk_commands(node) -> list[list[str]]:
    # parcurg arborele bashlex si dau fiecare comanda simpla ca lista de cuvinte
    commands = []
    if node.kind == "command":
        commands.append(extract_words(node))
    elif node.kind in ("list", "compound"):
        for child in getattr(node, "list", []):
            commands.extend(walk_commands(child))
    elif node.kind == "pipeline":
        for child in getattr(node, "parts", []):
            commands.extend(walk_commands(child))
    for child in getattr(node, "parts", []):
        if child.kind != "word":
            commands.extend(walk_commands(child))
    return commands


# bashlex se incurca la lucruri ca ">=~1.0" din cauza expansiunii tildei
# asa ca scot tilda inainte de parsare si o pun la loc dupa
def _sanitize_for_bashlex(run_value: str) -> str:
    return re.sub(r"([=<>~])~", r"\1TILDE", run_value)


# optiuni pip/apt care iau o valoare dupa ele, le sar pe amandoua
_FLAGS_WITH_ARG = {
    "-t", "--target", "--root", "--prefix", "--user",
    "--index-url", "--extra-index-url",
    "-r", "-c", "--constraint", "--requirement",
}


def _parse_install_args(words: list[str], manager: str) -> list[dict]:
    # scot numele si versiunile pachetelor din argumentele de dupa install
    packages = []
    skip_next = False

    for word in words:
        if skip_next:
            skip_next = False
            continue

        if word.startswith("-"):
            if word in _FLAGS_WITH_ARG:
                skip_next = True
            continue

        # URL-urile si caile nu sunt nume de pachete
        if word.startswith(("http://", "https://", "/", ".")):
            continue

        name, version = word, None

        if manager == "pip":
            parts = re.split(r"[=<>!~]+", word, maxsplit=1)
            name = parts[0]
            version = parts[1] if len(parts) > 1 else None
        elif manager == "apt" and "=" in word:
            name, version = word.split("=", 1)
        elif manager == "apk":
            name = re.split(r"[=~]", word, maxsplit=1)[0]
        elif manager == "npm" and "@" in word and not word.startswith("@"):
            name = word.split("@")[0]

        if name and name not in SKIP_PACKAGES and not name.startswith("#"):
            packages.append({"name": name, "manager": manager, "version": version})

    return packages


def _parse_from_distro(content: str) -> str | None:
    # detectez distributia imaginii de baza, ca sa aleg ecosistemul OSV pentru apt
    if not DockerfileParser:
        return None
    try:
        dfp = DockerfileParser(fileobj=io.BytesIO(content.encode()))
        instructions = dfp.structure
    except Exception:
        return None

    for instr in instructions:
        if instr["instruction"] != "FROM":
            continue
        value = instr["value"].strip().split(" AS ")[0].split(" as ")[0].strip()
        lower = value.lower().split("/")[-1].split("@")[0]
        name = lower.split(":")[0]

        if name in ("debian", "bitnami/debian"):
            return "Debian"
        if name in ("ubuntu", "ubuntu-debootstrap"):
            return "Ubuntu"
        if name == "alpine":
            return "Alpine"
        if name in ("centos", "rockylinux", "almalinux", "fedora", "rhel"):
            return "Red Hat"
        # etichete de tip python:3.12-slim-bookworm
        if "debian" in lower or "slim" in lower:
            return "Debian"
        if "alpine" in lower:
            return "Alpine"
    return None


def _parse_run_with_bashlex(run_value: str) -> list[list[str]] | None:
    # incerc intai bashlex; None inseamna ca parsarea a esuat
    if not bashlex:
        return None
    sanitized = _sanitize_for_bashlex(run_value)
    try:
        nodes = bashlex.parse(sanitized)
    except Exception as exc:
        logger.info("  bashlex couldn't parse RUN: %s", exc)
        return None
    commands = []
    for node in nodes:
        for words in walk_commands(node):
            words = [w.replace("TILDE", "~") for w in words]
            commands.append(words)
    return commands


def _parse_run_fallback(run_value: str) -> list[list[str]]:
    # impartire simpla dupa && si ; cand bashlex nu reuseste
    normalized = run_value.replace("\\\n", " ").replace("\\\r\n", " ")
    out = []
    for segment in re.split(r"&&|;", normalized):
        words = segment.strip().split()
        if words:
            out.append(words)
    return out


def parse_packages_from_dockerfile(content: str) -> list[dict]:
    # intorc toate pachetele instalate de o linie RUN: [{name, manager, version}, ...]
    if not DockerfileParser:
        logger.warning("dockerfile-parse missing, skipping package parsing")
        return []

    try:
        dfp = DockerfileParser(fileobj=io.BytesIO(content.encode()))
        instructions = dfp.structure
    except Exception as exc:
        logger.warning("Failed to parse Dockerfile: %s", exc)
        return []

    packages = []
    for instr in instructions:
        if instr["instruction"] != "RUN":
            continue
        cmds = _parse_run_with_bashlex(instr["value"]) or _parse_run_fallback(instr["value"])

        for words in cmds:
            if not words:
                continue
            binary = words[0].split("/")[-1]
            mgr_info = PKG_MANAGERS.get(binary)
            if not mgr_info:
                continue
            subcmd, label = mgr_info
            try:
                idx = words.index(subcmd)
            except ValueError:
                continue
            packages.extend(_parse_install_args(words[idx + 1:], label))

    # elimin duplicatele dupa (manager, name), pastrez prima aparitie
    seen = set()
    unique = []
    for p in packages:
        key = (p["manager"], p["name"])
        if key not in seen:
            seen.add(key)
            unique.append(p)

    logger.info("Parsed %d unique package(s)", len(unique))
    return unique
