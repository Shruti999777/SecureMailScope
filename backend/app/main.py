"""
SecureMailScope - FastAPI Application Entrypoint
Cryptographic Security Posture Assessment for Email Traffic (SMTP, IMAP, POP3, TLS, X.509)
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pathlib import Path

from app.config import settings
from app.database import init_db
from app.api.upload import router as upload_router
from app.api.analysis import router as analysis_router
from app.api.export import router as export_router
from app.api.ml import router as ml_router
from app.api.health import router as health_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: initialize database tables
    init_db()
    yield
    # Shutdown: clean up if needed


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Automated Cryptographic Security Posture & Behavioral Anomaly Assessment for Email Traffic.",
    lifespan=lifespan
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register Routers
app.include_router(upload_router)
app.include_router(analysis_router)
app.include_router(export_router)
app.include_router(ml_router)
app.include_router(health_router)

# Mount frontend static files if built
frontend_dist = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"
if frontend_dist.exists():
    app.mount("/", StaticFiles(directory=str(frontend_dist), html=True), name="static")


@app.get("/")
def root():
    return {
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "description": "SecureMailScope Cryptographic Security Posture Assessment API",
        "docs": "/docs",
        "api_endpoints": {
            "upload": "/api/upload",
            "analyses": "/api/analyses",
            "analysis_detail": "/api/analysis/{id}",
            "sessions": "/api/analysis/{id}/sessions",
            "findings": "/api/analysis/{id}/findings",
            "certificates": "/api/analysis/{id}/certificates",
            "risk": "/api/analysis/{id}/risk",
            "export_pdf": "/api/analysis/{id}/export/pdf",
            "export_html": "/api/analysis/{id}/export/html",
            "export_json": "/api/analysis/{id}/export/json",
            "ml_metrics": "/api/ml/metrics",
            "health": "/api/health"
        }
    }
