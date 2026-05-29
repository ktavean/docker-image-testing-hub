# tin toate joburile in memorie, fara baza de date
# cand o scanare se termina, frontendul salveaza rezultatul in localStorage,
# asa ca backendul nu trebuie sa pastreze nimic
import asyncio
import uuid
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Job:
    id:    str
    kind:  str    # dockerfile_compose, image sau combined
    label: str
    files: list
    scanners: dict

    # imaginea apare doar la scanarile combinate (Dockerfile + arhiva/referinta)
    # daca exista, procesul de lucru ruleaza si dive + trivy pe ea
    image_input: dict | None = None

    status:       str = "queued"   # queued, running, completed, failed, cancelled
    created_at:   str = ""
    started_at:   str | None = None
    completed_at: str | None = None
    error:        str | None = None

    # astea se completeaza la final, inainte de evenimentul de finalizare
    verdict:         str = "PENDING"
    total_findings:  int = 0
    summary:         dict | None = None
    hadolint_issues: int = 0
    trivy_issues:    int = 0
    package_issues:  int = 0
    cis_issues:      int = 0

    cancel_event: asyncio.Event = field(default_factory=asyncio.Event)
    events_q:     asyncio.Queue = field(default_factory=asyncio.Queue)

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.utcnow().isoformat()


class JobRegistry:
    # tine joburile active si coada de lucru, unul per proces

    def __init__(self, concurrency: int = 2):
        self.jobs:        dict[str, Job]     = {}
        self.queue:       asyncio.Queue[Job] = asyncio.Queue()
        self.concurrency: asyncio.Semaphore  = asyncio.Semaphore(concurrency)

    async def create(self, kind, label, files, scanners=None, image_input=None) -> Job:
        job = Job(id=str(uuid.uuid4()), kind=kind, label=label,
                  files=files, scanners=scanners or {},
                  image_input=image_input)
        self.jobs[job.id] = job
        await self.queue.put(job)
        return job

    def get(self, job_id: str) -> Job | None:
        return self.jobs.get(job_id)

    def remove(self, job_id: str) -> None:
        self.jobs.pop(job_id, None)


# instanta unica, o pornesc in main.py
_registry: JobRegistry | None = None


def init_registry(concurrency: int = 2) -> JobRegistry:
    global _registry
    _registry = JobRegistry(concurrency=concurrency)
    return _registry


def get_registry() -> JobRegistry:
    if _registry is None:
        raise RuntimeError("JobRegistry not initialised")
    return _registry
