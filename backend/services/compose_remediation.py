# remedierea fisierelor docker-compose
# incarc cu ruamel.yaml (pastreaza comentariile si ordinea cheilor), aplic
# modificari sigure, salvez; folosesc acelasi model de incredere
# ridicat/mediu/scazut ca la Dockerfile, ca interfata sa le arate la fel
#
# incredere ridicata (aplicate automat implicit):
#   - scot `privileged: true` de pe servicii (CIS-5.5)
#   - scot partajarea spatiilor de nume network/pid/ipc ale gazdei (CIS-5.6)
#   - adaug `security_opt: no-new-privileges:true` (CIS-5.14)
#   - inlocuiesc `cap_add: ALL` cu `cap_drop: ALL` (CIS-5.4)
#
# incredere medie (doar sugerate):
#   - adaug `cap_drop: ALL` la serviciile fara configurare de capabilitati
#   - adaug `read_only: true` cu un tmpfs minim pentru /tmp
#
# incredere scazuta (doar sugerate):
#   - adaug limite implicite de resurse (memory: 512M, cpus: 1.0)
import difflib
from io import StringIO
from typing import List, Tuple

from ruamel.yaml import YAML


def _yaml() -> YAML:
    y = YAML()
    y.preserve_quotes = True
    y.indent(mapping=2, sequence=4, offset=2)
    y.width = 200
    return y


def _load(content: str):
    return _yaml().load(StringIO(content))


def _dump(doc) -> str:
    out = StringIO()
    _yaml().dump(doc, out)
    return out.getvalue()


def _services(doc) -> dict:
    if not doc or not isinstance(doc, dict):
        return {}
    svcs = doc.get("services") or {}
    return svcs if isinstance(svcs, dict) else {}


# reparatiile individuale

def fix_remove_privileged(content: str) -> Tuple[str, List[str]]:
    doc = _load(content)
    msgs = []
    for name, svc in _services(doc).items():
        if not isinstance(svc, dict):
            continue
        if svc.get("privileged") is True:
            del svc["privileged"]
            msgs.append(f"[{name}] removed privileged: true (CIS-5.5)")
    return (_dump(doc), msgs) if msgs else (content, [])


def fix_remove_host_namespaces(content: str) -> Tuple[str, List[str]]:
    doc = _load(content)
    msgs = []
    for name, svc in _services(doc).items():
        if not isinstance(svc, dict):
            continue
        for key in ("network_mode", "pid", "ipc", "uts"):
            if svc.get(key) == "host":
                del svc[key]
                msgs.append(f"[{name}] removed {key}: host (CIS-5.6)")
    return (_dump(doc), msgs) if msgs else (content, [])


def fix_no_new_privileges(content: str) -> Tuple[str, List[str]]:
    doc = _load(content)
    msgs = []
    for name, svc in _services(doc).items():
        if not isinstance(svc, dict):
            continue
        existing = svc.get("security_opt") or []
        if not isinstance(existing, list):
            existing = [existing]
        if any("no-new-privileges" in str(s) for s in existing):
            continue
        existing.append("no-new-privileges:true")
        svc["security_opt"] = existing
        msgs.append(f"[{name}] added security_opt: no-new-privileges:true (CIS-5.14)")
    return (_dump(doc), msgs) if msgs else (content, [])


def fix_drop_cap_all(content: str) -> Tuple[str, List[str]]:
    # daca un serviciu are `cap_add: [ALL]`, il scot si pun `cap_drop: [ALL]` in loc
    doc = _load(content)
    msgs = []
    for name, svc in _services(doc).items():
        if not isinstance(svc, dict):
            continue
        cap_add = svc.get("cap_add")
        if not isinstance(cap_add, list):
            continue
        if not any(str(c).upper() == "ALL" for c in cap_add):
            continue
        del svc["cap_add"]
        existing_drop = svc.get("cap_drop") or []
        if not any(str(c).upper() == "ALL" for c in existing_drop):
            existing_drop = ["ALL"]
        svc["cap_drop"] = existing_drop
        msgs.append(f"[{name}] replaced cap_add: ALL with cap_drop: ALL (CIS-5.4)")
    return (_dump(doc), msgs) if msgs else (content, [])


def fix_cap_drop_all(content: str) -> Tuple[str, List[str]]:
    doc = _load(content)
    msgs = []
    for name, svc in _services(doc).items():
        if not isinstance(svc, dict):
            continue
        if "cap_drop" in svc or "cap_add" in svc:
            continue
        svc["cap_drop"] = ["ALL"]
        msgs.append(f"[{name}] added cap_drop: [ALL] (CIS-5.4)")
    return (_dump(doc), msgs) if msgs else (content, [])


def fix_read_only(content: str) -> Tuple[str, List[str]]:
    doc = _load(content)
    msgs = []
    for name, svc in _services(doc).items():
        if not isinstance(svc, dict):
            continue
        if svc.get("read_only") is True:
            continue
        svc["read_only"] = True
        existing_tmpfs = svc.get("tmpfs") or []
        if isinstance(existing_tmpfs, str):
            existing_tmpfs = [existing_tmpfs]
        if not any("/tmp" in str(t) for t in existing_tmpfs):
            existing_tmpfs.append("/tmp:size=64M,mode=1777")
        svc["tmpfs"] = existing_tmpfs
        msgs.append(f"[{name}] added read_only: true + tmpfs for /tmp (CIS-5.13)")
    return (_dump(doc), msgs) if msgs else (content, [])


def fix_resource_limits(content: str) -> Tuple[str, List[str]]:
    doc = _load(content)
    msgs = []
    for name, svc in _services(doc).items():
        if not isinstance(svc, dict):
            continue
        deploy = svc.get("deploy") or {}
        resources = deploy.get("resources") or {}
        limits = resources.get("limits") or {}
        added = []
        if "memory" not in limits:
            limits["memory"] = "512M"
            added.append("memory: 512M")
        if "cpus" not in limits:
            limits["cpus"] = "1.0"
            added.append("cpus: 1.0")
        if not added:
            continue
        resources["limits"] = limits
        deploy["resources"] = resources
        svc["deploy"] = deploy
        msgs.append(f"[{name}] added resource limits ({', '.join(added)}) (CIS-5.11/5.12)")
    return (_dump(doc), msgs) if msgs else (content, [])


FIXERS = [
    {"id": "compose_remove_privileged", "rule": "CIS-5.5",
     "description": "Remove privileged: true from services",
     "confidence": "HIGH", "fn": fix_remove_privileged},
    {"id": "compose_remove_host_ns", "rule": "CIS-5.6",
     "description": "Remove host network/pid/ipc namespace sharing",
     "confidence": "HIGH", "fn": fix_remove_host_namespaces},
    {"id": "compose_no_new_privileges", "rule": "CIS-5.14",
     "description": "Add security_opt: no-new-privileges:true to each service",
     "confidence": "HIGH", "fn": fix_no_new_privileges},
    {"id": "compose_drop_cap_all", "rule": "CIS-5.4",
     "description": "Replace cap_add: ALL with cap_drop: ALL",
     "confidence": "HIGH", "fn": fix_drop_cap_all},
    {"id": "compose_cap_drop_all", "rule": "CIS-5.4",
     "description": "Add cap_drop: ALL to services with no cap config",
     "confidence": "MEDIUM", "fn": fix_cap_drop_all},
    {"id": "compose_read_only", "rule": "CIS-5.13",
     "description": "Add read_only: true (with tmpfs for /tmp)",
     "confidence": "MEDIUM", "fn": fix_read_only},
    {"id": "compose_resource_limits", "rule": "CIS-5.11",
     "description": "Add default resource limits (memory, cpus)",
     "confidence": "LOW", "fn": fix_resource_limits},
]

_FIXER_MAP = {f["id"]: f for f in FIXERS}


def _diff(original: str, fixed: str, filename: str) -> str:
    return "".join(difflib.unified_diff(
        original.splitlines(keepends=True),
        fixed.splitlines(keepends=True),
        fromfile=f"a/{filename}",
        tofile=f"b/{filename}",
    ))


def preview_fixes(content: str, filename: str = "docker-compose.yml") -> list:
    results = []
    for fixer in FIXERS:
        try:
            new, applied = fixer["fn"](content)
        except Exception:
            continue
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
