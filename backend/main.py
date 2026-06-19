import asyncio
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from services.jobstate import init_registry
from worker import worker_loop
from routers import jobs, image_jobs, remediate, report

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    registry = init_registry(concurrency=2)
    worker = asyncio.create_task(worker_loop(registry))
    logger.info("DHH v0.8 started — in-memory registry, no DB")
    try:
        yield
    finally:
        worker.cancel()
        try:
            await worker
        except asyncio.CancelledError:
            pass


app = FastAPI(title="Docker Hardening Hub", version="0.8.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
app.include_router(jobs.router,       prefix="/api", tags=["jobs"])
app.include_router(image_jobs.router, prefix="/api", tags=["image_jobs"])
app.include_router(remediate.router,  prefix="/api", tags=["remediate"])
app.include_router(report.router,     prefix="/api", tags=["report"])


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "0.8.0"}

STATIC_DIR = "/app/static"
if os.path.exists(STATIC_DIR):
    app.mount("/assets", StaticFiles(directory=f"{STATIC_DIR}/assets"), name="assets")

    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        return FileResponse(f"{STATIC_DIR}/index.html")
