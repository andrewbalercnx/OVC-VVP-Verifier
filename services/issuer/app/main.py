"""VVP Issuer FastAPI application."""
import logging
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse

from common.vvp.core.logging import configure_logging
from app.api import health, identity
from app.keri.identity import get_identity_manager, close_identity_manager

# Web directory for static files
WEB_DIR = Path(__file__).parent.parent / "web"

configure_logging()
log = logging.getLogger("vvp-issuer")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler for startup/shutdown."""
    # Startup: Initialize identity manager
    log.info("Starting VVP Issuer service...")
    try:
        await get_identity_manager()
        log.info("VVP Issuer service started")
    except Exception as e:
        log.error(f"Failed to initialize identity manager: {e}")
        raise

    yield

    # Shutdown: Close identity manager
    log.info("Shutting down VVP Issuer service...")
    await close_identity_manager()
    log.info("VVP Issuer service stopped")


app = FastAPI(
    title="VVP Issuer",
    version="0.1.0",
    description="VVP Credential Issuer Service",
    lifespan=lifespan,
)

# Include routers
app.include_router(health.router)
app.include_router(identity.router)


@app.middleware("http")
async def request_logging(request: Request, call_next):
    """Log all requests with timing."""
    start = time.time()
    response = await call_next(request)
    duration_ms = int((time.time() - start) * 1000)

    log.info(
        f"request_complete status={response.status_code} duration_ms={duration_ms}",
        extra={
            "route": request.url.path,
            "method": request.method,
            "status": response.status_code,
        },
    )
    return response


@app.get("/version")
def version():
    """Return service version."""
    return {"git_sha": os.getenv("GIT_SHA", "unknown")}


@app.get("/create", response_class=FileResponse)
def create_identity_ui():
    """Serve the identity creation web UI."""
    return FileResponse(WEB_DIR / "create.html", media_type="text/html")
