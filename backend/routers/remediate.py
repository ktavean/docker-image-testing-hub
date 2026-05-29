# remedierea e fara stare: frontendul trimite continutul fisierului (il are
# din incarcarea initiala, salvat in localStorage), iar serverul intoarce
# reparatiile propuse sau aplicate
# doua tipuri se pot remedia: dockerfile (linting + bune practici) si
# compose (intarire dupa CIS Capitolul 5); restul (arhive de imagine) ajung in skipped
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from services.remediation         import apply_fixes  as df_apply,    preview_fixes  as df_preview,    FIXERS  as DF_FIXERS
from services.compose_remediation import apply_fixes  as cmp_apply,   preview_fixes  as cmp_preview,   FIXERS  as CMP_FIXERS

router = APIRouter()


class ScanFile(BaseModel):
    name: str
    kind: str                          # 'dockerfile' | 'compose' | 'image' | ...
    content: str | None = None         # absent for image-mode tarball inputs


class PreviewRequest(BaseModel):
    files: list[ScanFile] = Field(default_factory=list)


class ApplyRequest(BaseModel):
    files: list[ScanFile] = Field(default_factory=list)
    fixes: dict[str, list[str]] | None = None   # filename → [fix_ids]; None = apply all


# aleg motorul dupa tipul fisierului

def _engine(kind: str):
    # intorc (preview, apply, all_fix_ids) pentru tipul dat, sau None
    if kind == "dockerfile":
        return df_preview,  df_apply,  [f["id"] for f in DF_FIXERS]
    if kind == "compose":
        return cmp_preview, cmp_apply, [f["id"] for f in CMP_FIXERS]
    return None


def _partition(files: list[ScanFile]):
    # impart fisierele in (remediabile, ignorate)
    remediable, skipped = [], []
    for f in files:
        if f.content is None:
            skipped.append(f)
            continue
        if _engine(f.kind) is None:
            skipped.append(f)
            continue
        remediable.append(f)
    return remediable, skipped


def _skipped_payload(sk: list[ScanFile], with_reason: bool = False) -> list[dict]:
    out = []
    for f in sk:
        item = {"file": f.name, "kind": f.kind}
        if with_reason:
            if f.content is None:
                item["reason"] = "No content available (image-mode upload)"
            else:
                item["reason"] = f"Remediation not supported for kind '{f.kind}'"
        out.append(item)
    return out


# rutele

@router.post("/remediate/preview")
async def remediate_preview(body: PreviewRequest):
    if not body.files:
        raise HTTPException(400, "No files provided")

    remediable, skipped = _partition(body.files)
    per_file = []
    for f in remediable:
        preview, _apply, _all_ids = _engine(f.kind)
        per_file.append({
            "file":           f.name,
            "kind":           f.kind,
            "proposed_fixes": preview(f.content, f.name),
        })

    return {
        "files":            per_file,
        "skipped":          _skipped_payload(skipped, with_reason=True),
        "remediable_count": len(remediable),
        "skipped_count":    len(skipped),
    }


@router.post("/remediate/apply")
async def remediate_apply(body: ApplyRequest):
    if not body.files:
        raise HTTPException(400, "No files provided")

    remediable, skipped = _partition(body.files)
    if not remediable:
        return {
            "file_count":  0,
            "total_fixes": 0,
            "files":       [],
            "skipped":     _skipped_payload(skipped),
            "message":     "No remediable files in this scan.",
        }

    results = []
    for f in remediable:
        _preview, apply, all_ids = _engine(f.kind)
        fix_ids = body.fixes.get(f.name, []) if body.fixes else all_ids
        fixed, applied = apply(f.content, fix_ids)
        results.append({
            "file":              f.name,
            "kind":              f.kind,
            "fixes_applied":     applied,
            "fix_count":         len(applied),
            "fixed_dockerfile":  fixed,    # keep legacy key for frontend compat
            "fixed_content":     fixed,    # new generic alias
        })

    return {
        "file_count":  len(results),
        "total_fixes": sum(r["fix_count"] for r in results),
        "files":       results,
        "skipped":     _skipped_payload(skipped),
    }
