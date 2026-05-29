# procesul care lucreaza in fundal: ia joburi din coada, ruleaza scanarea
# potrivita si trimite evenimentele mai departe spre SSE
# evenimentul de finalizare duce tot rezultatul, ca frontendul sa-l salveze
# in localStorage fara sa mai ceara inca o data
import asyncio
import logging
import os
import tempfile
from datetime import datetime

from services.jobstate import Job, JobRegistry
from services.scoring import compute_score, compute_image_score
from services.scanner import run_all_scanners_multi, stream_trivy_for_image_input
from services.dive_scanner import stream_dive

logger = logging.getLogger("worker")

MAX_FILE_BYTES = 1 * 1024 * 1024   # 1 MB per fisier Dockerfile/Compose
SCAN_TIMEOUT_SECONDS       = 120
SCAN_TIMEOUT_SECONDS_IMAGE = 360   # dive pe o imagine de 500 MB dureaza

DEFAULT_SCANNERS = {"hadolint": True, "trivy_config": True, "trivy_secret": True,
                    "trivy_image": True, "package": True, "cis": True}


async def _drain(
    job: Job, source, timeout: int,
) -> tuple[list[dict], str, str | None]:
    # scot evenimentele din generator si le pun in coada
    # respect anularea jobului si o limita de timp
    # intorc (evenimente, stare, eroare), starea fiind completed/cancelled/failed
    events: list[dict] = []

    # Construim lista de evenimente in paralel cu coada SSE, ca sa putem
    # da intregul jurnal la compute_score si la evenimentul de finalizare.
    async def push(ev: dict):
        events.append(ev)
        await job.events_q.put(ev)

    # Coroutina interioara e cea pe care o cronometreaza asyncio.wait_for.
    # Verificam semnalul de anulare intre evenimente: asta e granularitatea
    # anularii. Un scaner aflat in mijlocul unui subproces nu poate fi
    # intrerupt, dar fiecare scaner are propria limita de timp (in
    # scanner.py), ceea ce tine pasii individuali sub control.
    async def loop():
        async for ev in source:
            if job.cancel_event.is_set():
                await push({"tool": "system", "type": "warning",
                            "message": "✗ Scan cancelled by user"})
                raise asyncio.CancelledError
            await push(ev)

    try:
        await asyncio.wait_for(loop(), timeout=timeout)
        return events, "completed", None
    except asyncio.CancelledError:
        # Ridicata de loop() cand se declanseaza anularea; evenimentul de
        # avertizare a fost deja trimis.
        return events, "cancelled", None
    except asyncio.TimeoutError:
        await push({"tool": "system", "type": "error",
                    "message": f"⚠ Scan timed out after {timeout}s"})
        return events, "failed", "Scan timed out"
    except Exception as exc:
        # Eroare in pipeline sau cadere a unui scaner. O logam pe server si
        # afisam mesajul utilizatorului in consola live.
        logger.exception("Pipeline error on job %s", job.id)
        await push({"tool": "system", "type": "error",
                    "message": f"✗ {exc!s}"})
        return events, "failed", str(exc)


def _scan_record(job: Job, events: list[dict]) -> dict:
    # asta e ce salveaza frontendul in localStorage
    # Pentru scanarile combinate atasam doar metadatele imaginii (nume +
    # tip), niciodata octetii arhivei. Frontendul foloseste asta ca sa
    # arate in istoric ca scanarea a inclus o arhiva, fara sa umfle stocarea.
    image_meta = None
    if job.image_input:
        image_meta = {
            "name": job.image_input.get("name"),
            "kind": job.image_input.get("kind"),
            "ref":  job.image_input.get("ref"),
        }
    return {
        "id":              job.id,
        "job_kind":        job.kind,
        "label":           job.label,
        "filename":        job.label,
        "files":           job.files,
        "image_input":     image_meta,
        "events":          events,
        "verdict":         job.verdict,
        "total_findings":  job.total_findings,
        "summary":         job.summary,
        "hadolint_issues": job.hadolint_issues,
        "trivy_issues":    job.trivy_issues,
        "package_issues":  job.package_issues,
        "cis_issues":      job.cis_issues,
        "job_status":      job.status,
        "created_at":      job.created_at,
        "started_at":      job.started_at,
        "completed_at":    job.completed_at,
        "worker_error":    job.error,
    }


async def _finalize(job: Job, events: list[dict], status: str, error: str | None = None):
    # pun starea finala si trimit evenimentul de finalizare
    job.status       = status
    job.completed_at = datetime.utcnow().isoformat()
    if error:
        job.error = error
    await job.events_q.put({
        "tool":      "system",
        "type":      "finish",
        "scan_id":   job.id,
        "cancelled": status == "cancelled",
        "failed":    status == "failed",
        "scan":      _scan_record(job, events),
    })


async def _process_dockerfile_compose_job(job: Job):
    # Verificare defensiva a dimensiunii (ruta o impune si ea).
    for f in job.files:
        if len(f.get("content", "").encode()) > MAX_FILE_BYTES:
            await _finalize(job, [], "failed", f"File {f['name']} exceeds 1 MB limit")
            return

    scanners = job.scanners or DEFAULT_SCANNERS

    tmpdir = tempfile.mkdtemp(prefix="dhh_")
    saved = []
    try:
        for f in job.files:
            path = os.path.join(tmpdir, f["name"])
            with open(path, "w", encoding="utf-8") as out:
                out.write(f.get("content", ""))
            saved.append({"name": f["name"], "path": path})

        # Faza 1: scannerele pe fisierele de sursa.
        events, status, error = await _drain(
            job, run_all_scanners_multi(saved, scanners), SCAN_TIMEOUT_SECONDS,
        )

        # Faza 2: pipeline-ul optional de imagine, dupa construire.
        # Cand utilizatorul a trimis o scanare combinata (Dockerfile/compose
        # + arhiva sau referinta), golim si evenimentele dive + trivy.
        if status == "completed" and job.image_input is not None:
            async def _image_pipeline():
                img_label = job.image_input.get("name") or job.image_input.get("ref") or "image"
                async for ev in stream_dive(job.image_input, img_label):
                    yield ev
                async for ev in stream_trivy_for_image_input(job.image_input, img_label):
                    yield ev

            img_events, img_status, img_error = await _drain(
                job, _image_pipeline(), SCAN_TIMEOUT_SECONDS_IMAGE,
            )
            events.extend(img_events)
            if img_status != "completed":
                status, error = img_status, img_error

        if status == "completed":
            scoring = compute_score(events)
            # Adaugam categoriile de imagine cand exista evenimente de imagine.
            if job.image_input is not None:
                from services.scoring import compute_image_score
                img_scoring = compute_image_score(events)
                # Reunim categoriile de imagine cu cele de sursa.
                scoring.setdefault("categories", {}).update(img_scoring.get("categories", {}))
                scoring["image_summary"] = img_scoring.get("image_summary", {})
                # Verdict: cel mai sever dintre cele doua.
                img_verdict = img_scoring.get("verdict", "APPROVED")
                cur_verdict = scoring.get("verdict", "APPROVED")
                if {img_verdict, cur_verdict} & {"POLICY_REJECTED"}:
                    scoring["verdict"] = "POLICY_REJECTED"
                elif {img_verdict, cur_verdict} & {"WARNING"}:
                    scoring["verdict"] = "WARNING"
                scoring["total_findings"] = (
                    scoring.get("total_findings", 0)
                    + img_scoring.get("total_findings", 0)
                )
            job.verdict        = scoring["verdict"]
            job.total_findings = scoring["total_findings"]
            job.summary        = scoring
            # Contoarele per instrument vin din evenimentul de sumar emis de scaner.
            summary_ev = next((e for e in events if e.get("type") == "summary"), {})
            job.hadolint_issues = summary_ev.get("hadolint", 0)
            job.trivy_issues    = summary_ev.get("trivy",    0)
            job.package_issues  = summary_ev.get("package",  0)
            job.cis_issues      = summary_ev.get("cis",      0)

        await _finalize(job, events, status, error)
        logger.info("Job %s %s — verdict=%s", job.id, status, job.verdict)
    finally:
        for s in saved:
            try: os.unlink(s["path"])
            except OSError: pass
        try: os.rmdir(tmpdir)
        except OSError: pass
        # Stergem arhiva imaginii daca scanarea combinata a inclus una.
        if job.image_input and job.image_input.get("kind") == "tarball":
            try: os.unlink(job.image_input["path"])
            except OSError: pass


async def _process_image_job(job: Job):
    if not job.files:
        await _finalize(job, [], "failed", "Image job has no input")
        return

    image_input = job.files[0]
    name = image_input.get("name") or image_input.get("ref") or "image"
    cleanup_path = image_input.get("path") if image_input.get("kind") == "tarball" else None

    try:
        # Combinam dive + trivy intr-un singur flux. Ordinea conteaza doar
        # pentru lizibilitatea jurnalului; ambele consuma aceeasi imagine
        # in mod independent (dive o aduce ca arhiva, trivy --input scaneaza
        # arhiva direct, ori `trivy image <ref>` pentru referinte de registru).
        async def _combined():
            async for ev in stream_dive(image_input, name):
                yield ev
            async for ev in stream_trivy_for_image_input(image_input, name):
                yield ev

        events, status, error = await _drain(
            job, _combined(), SCAN_TIMEOUT_SECONDS_IMAGE,
        )

        if status == "completed":
            scoring = compute_image_score(events)
            job.verdict        = scoring["verdict"]
            job.total_findings = scoring["total_findings"]
            job.summary        = scoring

        await _finalize(job, events, status, error)
        logger.info("Image job %s %s — verdict=%s", job.id, status, job.verdict)
    finally:
        if cleanup_path:
            try: os.unlink(cleanup_path)
            except OSError: pass


async def _handle(job: Job, registry: JobRegistry):
    # rulez un job respectand limita de concurenta, apoi il scot
    async with registry.concurrency:
        job.status     = "running"
        job.started_at = datetime.utcnow().isoformat()
        try:
            if job.kind == "image":
                await _process_image_job(job)
            else:
                # 'dockerfile_compose' si 'combined' ajung amandoua aici; al
                # doilea ruleaza in plus pipeline-ul de imagine de dupa construire.
                await _process_dockerfile_compose_job(job)
        finally:
            # Santinela, ca orice client SSE conectat sa se deblocheze curat.
            await job.events_q.put(None)
            registry.remove(job.id)


async def worker_loop(registry: JobRegistry):
    # iau joburi din coada si pornesc cate o sarcina pentru fiecare
    logger.info("Worker loop started")
    while True:
        try:
            job = await registry.queue.get()
            asyncio.create_task(_handle(job, registry))
        except asyncio.CancelledError:
            logger.info("Worker loop cancelled")
            raise
        except Exception as exc:
            logger.error("Worker loop error: %s", exc)
            await asyncio.sleep(0.5)
