# aici se trimit joburile de analiza a imaginilor
# accept fie o arhiva docker-archive incarcata, fie o referinta de registru
# (skopeo o aduce fara demon); transmiterea si anularea refolosesc rutele din jobs.py
import os
import re
import uuid

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile

from services.jobstate import get_registry
from services.limiter import rate_limit

router = APIRouter()

# arhivele stau in /tmp fiindca nu am volum persistent /data
# procesul de lucru le sterge cand se termina scanarea
IMAGE_TARBALL_DIR = "/tmp/dhh_image_uploads"

MAX_TARBALL_BYTES = 500 * 1024 * 1024
ALLOWED_SUFFIXES  = (".tar", ".tar.gz", ".tgz")

# gramatica relaxata pentru referinte OCI: nume simplu, ns/nume,
# host/ns/nume, :tag optional, @sha256:digest optional
# ce e ciudat se respinge aici, iar skopeo respinge ce mai scapa
_REF_RE = re.compile(
    r"^[a-z0-9]+([._-][a-z0-9]+)*"
    r"(/[a-z0-9]+([._-][a-z0-9]+)*)*"
    r"(:[A-Za-z0-9_][A-Za-z0-9_.\-]{0,127})?"
    r"(@sha256:[a-f0-9]{64})?$"
)


def _is_valid_tar(data: bytes) -> bool:
    # verific ca fisierul chiar e tar sau tar comprimat, nu doar are extensia .tar
    # semnatura gzip, cazul .tar.gz / .tgz
    if data[:2] == b"\x1f\x8b":
        return True
    # antet tar POSIX ustar: semnatura "ustar" e la offsetul 257 in primul
    # bloc de 512 octeti; sub 263 octeti nu poate fi un tar valid
    return len(data) >= 263 and data[257:262] == b"ustar"


@router.post("/jobs/image")
async def submit_image_job(
    request: Request,
    file: UploadFile | None = File(None),
    image_ref: str | None = Form(None),
    _rl: None = Depends(rate_limit),
):
    has_file = file is not None and (file.filename or "") != ""
    has_ref  = image_ref is not None and image_ref.strip() != ""
    # exact unul dintre ele: has_file == has_ref e adevarat cand lipsesc
    # amandoua sau exista amandoua, ambele fiind greseli ale utilizatorului
    if has_file == has_ref:
        raise HTTPException(400, "Provide exactly one of `file` or `image_ref`")

    return await _submit_tarball(file) if has_file else await _submit_ref(image_ref.strip())


async def _submit_tarball(file: UploadFile) -> dict:
    name = os.path.basename(file.filename or "image.tar")
    if not name.lower().endswith(ALLOWED_SUFFIXES):
        raise HTTPException(400, f"{name}: only .tar / .tar.gz / .tgz accepted")

    raw = await file.read()
    if not raw:
        raise HTTPException(400, f"{name}: empty file")
    if len(raw) > MAX_TARBALL_BYTES:
        raise HTTPException(413, f"{name}: exceeds {MAX_TARBALL_BYTES // 1024 // 1024} MB limit")
    if not _is_valid_tar(raw):
        raise HTTPException(400, f"{name}: not a valid tar archive")

    # salvez sub un nume UUID, ca numele dat de utilizator sa nu ajunga
    # pe disc ca atare; os.path.basename pazeste deja de traversare, dar UUID-ul
    # face problema irelevanta
    os.makedirs(IMAGE_TARBALL_DIR, exist_ok=True)
    disk_path = os.path.join(IMAGE_TARBALL_DIR, f"{uuid.uuid4().hex}.tar")
    with open(disk_path, "wb") as out:
        out.write(raw)

    job = await get_registry().create(
        kind="image", label=name,
        files=[{"name": name, "kind": "tarball", "path": disk_path}],
    )
    return {"job_id": job.id, "status": "queued", "label": name, "mode": "tarball"}


async def _submit_ref(ref: str) -> dict:
    if len(ref) > 512:
        raise HTTPException(400, "Image reference too long")
    if not _REF_RE.match(ref):
        raise HTTPException(400, f"Invalid image reference: {ref!r}")

    job = await get_registry().create(
        kind="image", label=ref,
        files=[{"name": ref, "kind": "ref", "ref": ref}],
    )
    return {"job_id": job.id, "status": "queued", "label": ref, "mode": "ref"}
