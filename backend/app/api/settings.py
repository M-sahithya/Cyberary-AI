"""
Settings & System Health API Endpoints
View and adjust LLM provider settings, Lab Mode toggles, and system service integrations.
Never exposes sensitive secret keys to the frontend.
"""

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from app.schemas.common import APIResponse
from app.security.authentication import get_current_user
from app.security.authorization import require_roles
from app.config.settings import settings
from app.models.user import User

router = APIRouter(prefix="/api/settings", tags=["Settings"])


class UpdateSettingsRequest(BaseModel):
    llm_provider: str = Field(default="ollama", description="ollama | openai")
    llm_model: str = Field(default="llama3", description="Model name")
    lab_mode: bool = Field(default=True, description="Strict lab isolation safety switch")


@router.get("", response_model=APIResponse)
async def get_system_settings(
    current_user: User = Depends(get_current_user),
):
    """Get active system configuration parameters and integration statuses."""
    return APIResponse.ok({
        "app_name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.APP_ENV,
        "lab_mode": settings.LAB_MODE,
        "llm_provider": settings.LLM_PROVIDER,
        "llm_model": settings.LLM_MODEL,
        "ollama_base_url": settings.OLLAMA_BASE_URL,
        "nvd_api_configured": bool(settings.NVD_API_KEY),
        "wazuh_configured": bool(settings.WAZUH_URL),
        "honeypot_host": settings.COWRIE_HOST,
        "honeypot_port": settings.COWRIE_PORT,
    })


@router.put("", response_model=APIResponse)
async def update_system_settings(
    body: UpdateSettingsRequest,
    current_user: User = Depends(require_roles(["ADMIN"])),
):
    """Update runtime platform settings."""
    settings.LLM_PROVIDER = body.llm_provider
    settings.LLM_MODEL = body.llm_model
    settings.LAB_MODE = body.lab_mode

    return APIResponse.ok({
        "message": "System settings updated successfully.",
        "llm_provider": settings.LLM_PROVIDER,
        "llm_model": settings.LLM_MODEL,
        "lab_mode": settings.LAB_MODE,
    })
