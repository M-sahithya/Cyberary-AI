"""
Cyberary-AI Backend — Main Application
Autonomous Offensive & Defensive Cyber Defense Platform

This is the main FastAPI application entry point.
Initializes middleware, routes, database connections, and error handlers.
"""

import logging
import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from app.config.settings import settings
from app.database.postgres import init_postgres, close_postgres
from app.database.mongodb import init_mongodb, close_mongodb
from app.utils.errors import register_exception_handlers
from app.api import auth, dashboard, websocket
from app.api.ssh_events import router as ssh_events_router
from app.services.ubuntu_ssh_collector import (
    start_ubuntu_ssh_collector,
    stop_ubuntu_ssh_collector,
)
from app.api.communication_security import router as communication_security_router


# ============================================================
# Logging Configuration
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)

logger = logging.getLogger("cyberary")


# ============================================================
# Rate Limiter
# ============================================================

limiter = Limiter(key_func=get_remote_address)


# ============================================================
# Application Lifespan
# ============================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application startup and shutdown lifecycle.
    """

    # --------------------------------------------------------
    # Startup
    # --------------------------------------------------------

    logger.info("=" * 60)
    logger.info("  🛡️  CYBERARY-AI — Starting Up")
    logger.info(f"  Environment: {settings.APP_ENV}")
    logger.info(f"  Lab Mode: {settings.LAB_MODE}")
    logger.info(
        f"  LLM Provider: {settings.LLM_PROVIDER} / {settings.LLM_MODEL}"
    )
    logger.info("=" * 60)

    # --------------------------------------------------------
    # Initialize PostgreSQL / SQLite
    # --------------------------------------------------------

    try:
        await init_postgres()
        logger.info("✅ Database connected and tables created.")

        from app.database.seed import seed_database

        await seed_database()
        logger.info("✅ Database seeded with default roles and admin.")

    except Exception as e:
        logger.error(f"❌ Database initialization failed: {e}")

    # --------------------------------------------------------
    # Initialize MongoDB
    # --------------------------------------------------------

    try:
        await init_mongodb()
        logger.info("✅ MongoDB connected and collections initialized.")

    except Exception as e:
        logger.error(f"❌ MongoDB connection failed: {e}")

    # --------------------------------------------------------
    # Start Ubuntu SSH Log Collector
    # --------------------------------------------------------

    await start_ubuntu_ssh_collector()

    # --------------------------------------------------------
    # Application Running
    # --------------------------------------------------------

    yield

    # --------------------------------------------------------
    # Shutdown
    # --------------------------------------------------------

    logger.info("🛡️  CYBERARY-AI — Shutting Down")

    await stop_ubuntu_ssh_collector()
    await close_postgres()
    await close_mongodb()

    logger.info("✅ All connections and collectors closed cleanly.")


# ============================================================
# Create FastAPI Application
# ============================================================

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "Autonomous Offensive & Defensive Cyber Defense Platform. "
        "Connects ethical attack simulation, dynamic AI honeypots, "
        "threat intelligence, MITRE ATT&CK mapping, vulnerability assessment, "
        "automated remediation, and a unified AI-powered SOC dashboard."
    ),
    docs_url="/docs",
    redoc_url="/redoc",

    # --------------------------------------------------------
    # Swagger UI Configuration
    # --------------------------------------------------------
    # Keeps Swagger's authorization state after browser reload.
    # This is useful for local development and API testing.
    # --------------------------------------------------------
    swagger_ui_parameters={
        "persistAuthorization": True
    },

    lifespan=lifespan,
)


# ============================================================
# Middleware
# ============================================================

# ------------------------------------------------------------
# Rate Limiting
# ------------------------------------------------------------

app.state.limiter = limiter

app.add_exception_handler(
    RateLimitExceeded,
    _rate_limit_exceeded_handler,
)


# ------------------------------------------------------------
# CORS
# ------------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# Error Handlers
# ============================================================

register_exception_handlers(app)


# ============================================================
# System Routes
# ============================================================

@app.get("/health", tags=["System"])
async def health_check():
    """
    System health check endpoint.
    """

    return {
        "success": True,
        "data": {
            "status": "healthy",
            "version": settings.APP_VERSION,
            "lab_mode": settings.LAB_MODE,
            "environment": settings.APP_ENV,
            "services": {
                "backend": "running",
                "llm_provider": settings.LLM_PROVIDER,
            },
        },
    }


# ============================================================
# API Routers
# ============================================================

from app.api import (
    auth,
    dashboard,
    websocket,
    threats,
    honeypot,
    vulnerabilities,
    cve,
    mitre,
    remediation,
    assets,
    agents,
    audit_logs,
    settings as settings_api,
    evaluation,
)


# ------------------------------------------------------------
# Register API Routers
# ------------------------------------------------------------

app.include_router(auth.router)
app.include_router(dashboard.router)
app.include_router(threats.router)
app.include_router(honeypot.router)
app.include_router(vulnerabilities.router)
app.include_router(cve.router)
app.include_router(mitre.router)
app.include_router(remediation.router)
app.include_router(assets.router)
app.include_router(agents.router)
app.include_router(audit_logs.router)
app.include_router(settings_api.router)
app.include_router(evaluation.router)
app.include_router(websocket.router)
app.include_router(ssh_events_router)
app.include_router(communication_security_router)


# ============================================================
# Root Route
# ============================================================

@app.get("/", tags=["System"])
async def root():
    """
    Root endpoint — returns API information.
    """

    return {
        "success": True,
        "data": {
            "message": "Cyberary-AI API",
            "version": settings.APP_VERSION,
            "docs": "/docs",
            "health": "/health",
        },
    }