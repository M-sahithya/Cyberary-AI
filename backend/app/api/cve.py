"""
CVE & NVD API Endpoints
Provides CVE lookup, CVSS metrics, affected software descriptions, and vendor advisories.
"""

from fastapi import APIRouter, Depends
from app.schemas.common import APIResponse
from app.security.authentication import get_current_user
from app.models.user import User
from app.services.nvd_service import fetch_cve_details, LOCAL_CVE_CATALOG

router = APIRouter(prefix="/api/cve", tags=["CVE"])


@router.get("", response_model=APIResponse)
async def list_cached_cves(
    current_user: User = Depends(get_current_user),
):
    """List indexed CVEs available in the lab repository."""
    items = list(LOCAL_CVE_CATALOG.values())
    return APIResponse.ok({"items": items, "total": len(items)})


@router.get("/{cve_id}", response_model=APIResponse)
async def get_cve_info(
    cve_id: str,
    current_user: User = Depends(get_current_user),
):
    """
    Search and retrieve live vulnerability details for a CVE ID from NVD API or verified catalog.
    """
    details = await fetch_cve_details(cve_id)
    return APIResponse.ok(details)
