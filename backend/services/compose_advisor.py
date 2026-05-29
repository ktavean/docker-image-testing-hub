# CIS Docker Benchmark v1.8.0, Capitolul 5 (configurarea la rulare)
# parcurg fisierul docker-compose si semnalez setarile riscante pe fiecare serviciu
# implementez verificarile care se mapeaza curat pe campurile compose: 5.4, 5.5,
# 5.6, 5.7, 5.8, 5.10, 5.11, 5.12, 5.13, 5.14, 5.16, 5.17, 5.22, 5.25, 5.31, 5.32
import logging
from dataclasses import dataclass
from typing import AsyncGenerator

try:
    import yaml
except ImportError:
    yaml = None

logger = logging.getLogger("compose_advisor")


@dataclass
class Finding:
    rule:        str
    title:       str
    severity:    str
    service:     str
    description: str
    suggestion:  str
    snippet:     str = ""


# cai de pe gazda pe care nu le vrem niciodata montate intr-un container (CIS 5.6)
SENSITIVE_HOST_PATHS = {
    "/", "/etc", "/etc/passwd", "/etc/shadow", "/etc/sudoers",
    "/proc", "/sys", "/dev", "/boot", "/var/log", "/var/lib/docker",
    "/usr", "/usr/local", "/lib", "/lib64", "/root", "/home",
}

# socketuri de runtime; montarea oricaruia inseamna control total pe gazda (CIS 5.32)
DOCKER_SOCKET_PATHS = {
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/var/run/podman/podman.sock",
    "/run/podman/podman.sock",
    "/run/containerd/containerd.sock",
}

# capabilitati care dau privilegii excesive (CIS 5.4)
DANGEROUS_CAPABILITIES = {
    "ALL":             "Grants every capability — equivalent to --privileged.",
    "SYS_ADMIN":       "Allows broad system administration; near-root inside container.",
    "SYS_PTRACE":      "Lets you attach to other processes — including other containers' memory.",
    "SYS_MODULE":      "Allows loading kernel modules.",
    "SYS_RAWIO":       "Raw I/O — direct device access.",
    "DAC_READ_SEARCH": "Bypasses file read permissions.",
    "DAC_OVERRIDE":    "Bypasses file permission checks entirely.",
    "NET_ADMIN":       "Full network admin — can configure host interfaces.",
    "MAC_ADMIN":       "Override MAC (AppArmor/SELinux) policies.",
    "MAC_OVERRIDE":    "Override MAC policies.",
    "SYS_BOOT":        "Can reboot/shut down the host.",
    "SYS_TIME":        "Can change the system clock.",
}


# ajutoare

def _as_list(v) -> list:
    # compose accepta si string si lista; aduc totul la lista
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _parse_host_port(p) -> int | None:
    # scot portul de pe gazda dintr-o intrare 'ports' din compose
    if isinstance(p, dict):
        hp = p.get("published")
        if isinstance(hp, str):
            try: return int(hp)
            except ValueError: return None
        return hp if isinstance(hp, int) else None

    # forme ca string: "8080", "8080:80", "127.0.0.1:8080:80", "8080:80/tcp"
    # portul gazdei e penultima bucata dintre doua puncte, sau singura daca
    # nu exista deloc; scot sufixul optional /tcp|/udp
    s = str(p).strip("\"'")
    parts = s.split(":")
    host_part = parts[-2] if len(parts) >= 2 else parts[0]
    try:
        return int(host_part.split("/")[0])
    except (ValueError, IndexError):
        return None


# verificarile pe reguli

def _check_5_5_privileged(name, svc, findings):
    if svc.get("privileged") is True:
        findings.append(Finding(
            rule="CIS-5.5", title="Privileged container",
            severity="critical", service=name,
            description="privileged: true gives the container all host devices and "
                        "disables seccomp/AppArmor/cap-dropping — basically root on host.",
            suggestion="Remove privileged: true. If you really need specific access, "
                       "grant individual capabilities with cap_add and specific devices.",
        ))


def _check_5_4_capabilities(name, svc, findings):
    for cap in _as_list(svc.get("cap_add")):
        cap_upper = str(cap).upper().replace("CAP_", "")
        if cap_upper in DANGEROUS_CAPABILITIES:
            findings.append(Finding(
                rule="CIS-5.4", title=f"Excessive capability: {cap_upper}",
                severity="critical" if cap_upper == "ALL" else "high",
                service=name,
                description=f"Granted {cap_upper}. {DANGEROUS_CAPABILITIES[cap_upper]}",
                suggestion="Drop the capability if not strictly needed. Use "
                           "cap_drop: ['ALL'] and add back only what's required "
                           "(usually NET_BIND_SERVICE for ports < 1024).",
            ))


def _check_5_6_host_volumes(name, svc, findings):
    # cai sensibile montate de pe gazda, plus verificarea speciala a montarii de socket
    for vol in svc.get("volumes") or []:
        # compose accepta si forma scurta (string) si forma lunga (dictionar)
        if isinstance(vol, dict):
            src, target = vol.get("source", ""), vol.get("target", "")
        elif isinstance(vol, str):
            parts = vol.split(":")
            src    = parts[0] if len(parts) >= 2 else ""
            target = parts[1] if len(parts) >= 2 else ""
        else:
            continue

        if not src.startswith("/"):
            continue  # volum cu nume / cale relativa, il sar

        # socketul Docker/Podman, regula separata, critica
        if src in DOCKER_SOCKET_PATHS or target in DOCKER_SOCKET_PATHS:
            findings.append(Finding(
                rule="CIS-5.32", title="Container runtime socket mounted",
                severity="critical", service=name,
                description=(
                    f"Mounts {src} into the container. Any process inside can drive "
                    f"the runtime — that's effectively root on the host."
                ),
                suggestion="Remove this mount. If the container genuinely needs to "
                           "manage other containers, put a socket-proxy in front "
                           "(e.g. Tecnativa/docker-socket-proxy) or use TLS over TCP.",
            ))
            continue

        if src in SENSITIVE_HOST_PATHS or any(
            src == p or src.startswith(p + "/") for p in SENSITIVE_HOST_PATHS
        ):
            findings.append(Finding(
                rule="CIS-5.6", title="Sensitive host directory mounted",
                severity="high", service=name,
                description=f"Mounts {src} from the host — exposes system config, "
                            f"user data, or kernel interfaces to the container.",
                suggestion="Mount only the specific files/subdirs you actually need. "
                           "Add :ro if reads are enough.",
            ))


def _check_5_7_ssh(name, svc, findings):
    # detectie sumara de SSH in container: numele imaginii + portul 22 mapat
    image = str(svc.get("image", "")).lower()
    if "ssh" in image and ("openssh" in image or "sshd" in image):
        findings.append(Finding(
            rule="CIS-5.7", title="SSH server in container image",
            severity="medium", service=name,
            description=f"Image '{svc.get('image')}' looks like it ships an SSH server.",
            suggestion="Use docker/kubectl exec for interactive access instead. "
                       "If you genuinely need SSH, terminate it at a bastion outside the container.",
        ))

    for p in svc.get("ports") or []:
        hp = _parse_host_port(p)
        if hp == 22:
            findings.append(Finding(
                rule="CIS-5.7", title="Port 22 (SSH) exposed",
                severity="medium", service=name,
                description="Service maps host port 22 — suggests SSH access into the container.",
                suggestion="Don't run sshd in containers; use exec for shell access.",
            ))
            break


def _check_5_8_privileged_ports(name, svc, findings):
    # maparea unui port privilegiat de gazda (<1024, fara 80/443) e de obicei inutila
    for p in svc.get("ports") or []:
        hp = _parse_host_port(p)
        if hp is not None and 0 < hp < 1024 and hp not in (80, 443):
            findings.append(Finding(
                rule="CIS-5.8", title=f"Privileged port mapped: {hp}",
                severity="medium", service=name,
                description=f"Binds host port {hp} (<1024). Privileged ports usually need "
                            f"root or extra capabilities on the host.",
                suggestion=f"Map an unprivileged port (e.g. {8000 + hp}:{hp}) and put a "
                           f"reverse proxy in front if you need :{hp} externally.",
            ))


def _check_namespace_sharing(name, svc, findings):
    # 5.10 / 5.16 / 5.17 / 5.31, partajarea spatiilor de nume ale gazdei
    if svc.get("network_mode") == "host":
        findings.append(Finding(
            rule="CIS-5.10", title="Host network namespace shared",
            severity="high", service=name,
            description="network_mode: host gives the container the host's network stack "
                        "— bypasses isolation, can sniff all traffic.",
            suggestion="Use a user-defined bridge or overlay network and map ports explicitly.",
        ))
    if svc.get("pid") == "host":
        findings.append(Finding(
            rule="CIS-5.16", title="Host PID namespace shared",
            severity="high", service=name,
            description="pid: host lets the container see and signal every host process.",
            suggestion="Remove pid: host.",
        ))
    if svc.get("ipc") == "host":
        findings.append(Finding(
            rule="CIS-5.17", title="Host IPC namespace shared",
            severity="medium", service=name,
            description="ipc: host shares System V IPC across containers and host.",
            suggestion="Remove ipc: host unless a specific IPC integration needs it.",
        ))
    if svc.get("userns_mode") == "host":
        findings.append(Finding(
            rule="CIS-5.31", title="Host user namespace shared",
            severity="high", service=name,
            description="userns_mode: host kills user-namespace remapping — UID 0 in the "
                        "container is UID 0 on the host.",
            suggestion="Remove userns_mode: host and configure userns-remap in daemon.json.",
        ))


def _check_resource_limits(name, svc, findings):
    # 5.11 / 5.12, limite de memorie si de procesor
    deploy_limits = (svc.get("deploy") or {}).get("resources", {}).get("limits", {})

    mem = svc.get("mem_limit") or deploy_limits.get("memory")
    if not mem:
        findings.append(Finding(
            rule="CIS-5.11", title="No memory limit",
            severity="low", service=name,
            description="No memory limit — an OOM or memory leak can take out other "
                        "containers and the host.",
            suggestion="Set mem_limit (v2) or deploy.resources.limits.memory (v3+).",
            snippet="    mem_limit: 512m",
        ))

    cpu = svc.get("cpus") or svc.get("cpu_shares") or deploy_limits.get("cpus")
    if not cpu:
        findings.append(Finding(
            rule="CIS-5.12", title="No CPU limit",
            severity="low", service=name,
            description="No CPU limit — a runaway process can starve everything else.",
            suggestion="Set cpus or deploy.resources.limits.cpus.",
            snippet="    cpus: '1.0'",
        ))


def _check_read_only(name, svc, findings):
    if not svc.get("read_only"):
        findings.append(Finding(
            rule="CIS-5.13", title="Root filesystem is writable",
            severity="low", service=name,
            description="Container root is writable. An attacker with code execution "
                        "can drop persistent payloads.",
            suggestion="Set read_only: true. Use tmpfs for paths that need writes (/tmp).",
            snippet="    read_only: true\n    tmpfs:\n      - /tmp",
        ))


def _check_no_new_privs(name, svc, findings):
    sec_opt = _as_list(svc.get("security_opt"))
    if not any("no-new-privileges" in str(o) for o in sec_opt):
        findings.append(Finding(
            rule="CIS-5.14", title="no-new-privileges not set",
            severity="low", service=name,
            description="Without no-new-privileges, setuid binaries can grant new "
                        "privileges to processes inside the container.",
            suggestion="Add 'no-new-privileges:true' to security_opt.",
            snippet="    security_opt:\n      - no-new-privileges:true",
        ))


def _check_seccomp_apparmor(name, svc, findings):
    # 5.22 / 5.25, nu dezactiva seccomp sau AppArmor
    for opt in _as_list(svc.get("security_opt")):
        s = str(opt).lower().strip()
        if s in ("seccomp=unconfined", "seccomp:unconfined"):
            findings.append(Finding(
                rule="CIS-5.22", title="Default seccomp profile disabled",
                severity="high", service=name,
                description="seccomp:unconfined leaves all ~400+ Linux syscalls available — "
                            "including ones used in container escapes.",
                suggestion="Remove seccomp:unconfined. Use the default profile or a custom one.",
            ))
        if s in ("apparmor=unconfined", "apparmor:unconfined"):
            findings.append(Finding(
                rule="CIS-5.25", title="AppArmor disabled",
                severity="high", service=name,
                description="apparmor:unconfined drops the default AppArmor profile.",
                suggestion="Remove apparmor:unconfined.",
            ))


# toate verificarile pe serviciu, in ordine
_CHECKS = [
    _check_5_5_privileged,
    _check_5_4_capabilities,
    _check_5_6_host_volumes,
    _check_5_7_ssh,
    _check_5_8_privileged_ports,
    _check_namespace_sharing,
    _check_resource_limits,
    _check_read_only,
    _check_no_new_privs,
    _check_seccomp_apparmor,
]


def analyze_compose(content: str) -> list[Finding]:
    if not yaml:
        logger.warning("PyYAML missing, skipping compose analysis")
        return []
    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        logger.warning("Failed to parse compose YAML: %s", exc)
        return []
    if not isinstance(data, dict):
        return []

    services = data.get("services") or {}
    if not isinstance(services, dict):
        return []

    findings: list[Finding] = []
    for svc_name, svc in services.items():
        if not isinstance(svc, dict):
            continue
        for check in _CHECKS:
            check(svc_name, svc, findings)

    logger.info("Compose Advisor: %d service(s), %d finding(s)", len(services), len(findings))
    return findings


def extract_images(content: str) -> list[str]:
    # scot fiecare valoare 'image:'; pasul Trivy pe imaginile din compose o foloseste
    if not yaml:
        return []
    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError:
        return []
    if not isinstance(data, dict):
        return []
    return [
        svc["image"]
        for svc in (data.get("services") or {}).values()
        if isinstance(svc, dict) and isinstance(svc.get("image"), str)
    ]


async def stream_compose_advisor(content: str, display_name: str) -> AsyncGenerator[dict, None]:
    yield {"tool": "compose-advisor", "type": "start", "file": display_name,
           "message": "▶ [compose-advisor] CIS Docker Benchmark v1.8.0 — Chapter 5..."}

    findings = analyze_compose(content)
    for f in findings:
        yield {
            "tool": "compose-advisor", "type": "issue", "file": display_name,
            "level": f.severity, "code": f.rule,
            "message": f"[{f.rule}] [{f.service}] {f.title}: {f.description}",
            "suggestion": f.suggestion,
            "snippet": f.snippet,
        }

    if not findings:
        yield {"tool": "compose-advisor", "type": "info", "file": display_name,
               "message": "✓ No CIS Chapter 5 issues found"}
    yield {"tool": "compose-advisor", "type": "done", "file": display_name,
           "message": f"■ Compose advisor complete — {len(findings)} recommendation(s)",
           "count": len(findings)}
