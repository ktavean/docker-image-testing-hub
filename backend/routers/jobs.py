# aici se trimit joburile si se transmit evenimentele in timp real pentru
# scanarile Dockerfile/Compose
# pe langa fisierele de sursa, ruta accepta si o imagine optionala (arhiva
# sau referinta de registru); daca exista, procesul de lucru ruleaza si
# pipeline-ul de imagine (dive + Trivy) dupa scannerele de sursa
# nu am ruta GET de stare: evenimentul de finalizare duce tot rezultatul,
# iar frontendul il salveaza in localStorage
import asyncio
import json
import os
import re
import uuid
from typing import List

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import StreamingResponse

from services.jobstate import get_registry
from services.limiter import rate_limit
from services.scanner import classify_file

router = APIRouter()

MAX_FILE_BYTES     = 1   * 1024 * 1024
MAX_TARBALL_BYTES  = 500 * 1024 * 1024
ALLOWED_KINDS      = ("dockerfile", "compose")
ALLOWED_TAR_SUFFIX = (".tar", ".tar.gz", ".tgz")
IMAGE_TARBALL_DIR  = "/tmp/dhh_image_uploads"

# gramatica relaxata pentru referinte OCI, la fel ca in image_jobs.py
_REF_RE = re.compile(
    r"^[a-z0-9]+([._-][a-z0-9]+)*"
    r"(/[a-z0-9]+([._-][a-z0-9]+)*)*"
    r"(:[A-Za-z0-9_][A-Za-z0-9_.\-]{0,127})?"
    r"(@sha256:[a-f0-9]{64})?$"
)

DEFAULT_SCANNERS = {
    "hadolint": True, "trivy_config": True, "trivy_secret": True,
    "trivy_image": True, "package": True, "cis": True,
}


def _is_valid_tar(data: bytes) -> bool:
    if data[:2] == b"\x1f\x8b":  # gzip
        return True
    return len(data) >= 263 and data[257:262] == b"ustar"


async def _persist_image_input(
    image_tarball: UploadFile | None,
    image_ref:     str | None,
) -> dict | None:
    # validez si salvez imaginea optionala
    # intorc dictionarul (aceeasi forma ca /api/jobs/image) sau None daca lipseste
    has_file = image_tarball is not None and (image_tarball.filename or "") != ""
    has_ref  = image_ref is not None and image_ref.strip() != ""

    if not has_file and not has_ref:
        return None
    if has_file and has_ref:
        raise HTTPException(400, "Provide at most one of `image_tarball` or `image_ref`")

    if has_file:
        name = os.path.basename(image_tarball.filename or "image.tar")
        if not name.lower().endswith(ALLOWED_TAR_SUFFIX):
            raise HTTPException(400, f"{name}: only .tar / .tar.gz / .tgz accepted as image tarball")
        raw = await image_tarball.read()
        if not raw:
            raise HTTPException(400, f"{name}: empty tarball")
        if len(raw) > MAX_TARBALL_BYTES:
            raise HTTPException(413, f"{name}: tarball exceeds {MAX_TARBALL_BYTES // 1024 // 1024} MB limit")
        if not _is_valid_tar(raw):
            raise HTTPException(400, f"{name}: not a valid tar archive")
        os.makedirs(IMAGE_TARBALL_DIR, exist_ok=True)
        disk_path = os.path.join(IMAGE_TARBALL_DIR, f"{uuid.uuid4().hex}.tar")
        with open(disk_path, "wb") as out:
            out.write(raw)
        return {"name": name, "kind": "tarball", "path": disk_path}

    ref = image_ref.strip()
    if len(ref) > 512 or not _REF_RE.match(ref):
        raise HTTPException(400, f"Invalid image reference: {ref!r}")
    return {"name": ref, "kind": "ref", "ref": ref}


@router.post("/jobs")
async def submit_job(
    request:       Request,
    files:         List[UploadFile] | None = File(None),
    scanners:      str                     = Form("{}"),
    image_tarball: UploadFile | None       = File(None),
    image_ref:     str | None              = Form(None),
    _rl:           None                    = Depends(rate_limit),
):
    # intai citesc imaginea optionala (poate fi arhiva sau referinta)
    image_input = await _persist_image_input(image_tarball, image_ref)

    # fisierele de sursa sunt optionale, dar trebuie sa existe macar unul
    # dintre {files, image_input}
    has_files = files is not None and any((uf.filename or "") for uf in files)
    if not has_files and image_input is None:
        raise HTTPException(400, "Provide at least one Dockerfile/compose file or an image input")

    try:
        selection = json.loads(scanners) if scanners else {}
    except json.JSONDecodeError:
        selection = {}
    final_scanners = {**DEFAULT_SCANNERS, **{k: bool(v) for k, v in selection.items()}}

    uploaded = []
    if has_files:
        for uf in files:
            raw = await uf.read()
            if len(raw) > MAX_FILE_BYTES:
                raise HTTPException(413, f"{uf.filename}: file exceeds 1 MB limit")
            name = os.path.basename(uf.filename or "unnamed")
            kind = classify_file(name)
            if kind not in ALLOWED_KINDS:
                raise HTTPException(
                    400, f"{name}: unsupported file type — upload Dockerfile or docker-compose.yml",
                )
            uploaded.append({"name": name, "content": raw.decode("utf-8", errors="replace"),
                             "kind": kind})

    # decid tipul jobului:
    #   - doar sursa            -> dockerfile_compose
    #   - sursa + imagine       -> combined (scannere sursa + pipeline imagine)
    #   - doar imagine          -> image (doar pipeline-ul de imagine)
    if uploaded and image_input:
        job_kind = "combined"
        label = uploaded[0]["name"] + (f" +{len(uploaded)-1} more" if len(uploaded) > 1 else "")
        label += f"  +  image:{image_input.get('name', '')}"
        job = await get_registry().create(
            kind=job_kind, label=label,
            files=uploaded, scanners=final_scanners,
            image_input=image_input,
        )
    elif uploaded:
        job_kind = "dockerfile_compose"
        label = uploaded[0]["name"] if len(uploaded) == 1 \
                else f"{uploaded[0]['name']} +{len(uploaded)-1} more"
        job = await get_registry().create(
            kind=job_kind, label=label,
            files=uploaded, scanners=final_scanners,
        )
    else:
        # doar imagine: trimit la procesul de imagine; files=[image_input]
        # respecta forma veche /api/jobs/image pe care o citeste _process_image_job
        job_kind = "image"
        label    = image_input.get("name") or image_input.get("ref") or "image"
        job = await get_registry().create(
            kind=job_kind, label=label,
            files=[image_input],
        )

    return {"job_id": job.id, "status": "queued", "label": job.label,
            "scanners": final_scanners,
            "kind": job_kind,
            "has_image_input": image_input is not None}


@router.get("/jobs/{job_id}/stream")
async def stream_job(job_id: str):
    job = get_registry().get(job_id)
    if job is None:
        raise HTTPException(404, "Job not found")

    async def event_gen():
        # anunt clientul ca s-a conectat inainte sa apara ceva de la procesul de lucru
        yield f"data: {json.dumps({'tool':'system','type':'init','scan_id':job_id,'message':'⚙ Job queued — waiting for worker...'})}\n\n"
        while True:
            try:
                ev = await job.events_q.get()
            except asyncio.CancelledError:
                # clientul s-a deconectat; las procesul de lucru sa continue
                return
            if ev is None:
                return  # worker sentinel
            yield f"data: {json.dumps(ev)}\n\n"
            if ev.get("type") == "finish":
                return

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.post("/jobs/{job_id}/cancel")
async def cancel_scan(job_id: str):
    job = get_registry().get(job_id)
    if job is None:
        raise HTTPException(404, "Job not found")
    if job.status not in ("queued", "running"):
        raise HTTPException(400, "Job is not running or queued")
    job.cancel_event.set()
    return {"job_id": job_id, "status": "cancelling"}
