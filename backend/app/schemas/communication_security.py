"""
Cyberary-AI Communication Security Gateway Schemas
"""

from typing import List, Optional, Dict, Any

from pydantic import BaseModel, Field, EmailStr


class CommunicationAnalyzeRequest(BaseModel):
    """
    Incoming email/message submitted for security analysis.
    """

    sender: str = Field(..., min_length=1, max_length=255)

    recipient: Optional[str] = Field(
        default=None,
        max_length=255,
    )

    subject: Optional[str] = Field(
        default=None,
        max_length=500,
    )

    body: str = Field(
        ...,
        min_length=1,
    )

    message_type: str = Field(
        default="EMAIL",
        description="EMAIL or MESSAGE",
    )

    urls: List[str] = Field(
        default_factory=list,
    )

    attachments: List[Dict[str, Any]] = Field(
        default_factory=list,
    )


class CommunicationSecurityResult(BaseModel):
    """
    Final security analysis result.
    """

    event_id: str

    classification: str

    risk_score: int = Field(
        ge=0,
        le=100,
    )

    confidence: float = Field(
        ge=0,
        le=100,
    )

    severity: str

    reason: Optional[str] = None

    recommended_action: str

    policy_decision: str

    human_review_required: bool

    notification_required: bool

    notification_level: Optional[str] = None

    sender_analysis: Optional[Dict[str, Any]] = None

    content_analysis: Optional[Dict[str, Any]] = None

    url_analysis: Optional[Dict[str, Any]] = None

    attachment_analysis: Optional[Dict[str, Any]] = None

    threat_intelligence: Optional[Dict[str, Any]] = None

    llm_analysis: Optional[Dict[str, Any]] = None


class CommunicationReviewRequest(BaseModel):
    """
    Human analyst review of a quarantined message.
    """

    decision: str = Field(
        ...,
        description="ALLOW or BLOCK",
    )

    reviewer: str = Field(
        ...,
        min_length=1,
        max_length=100,
    )

    comment: Optional[str] = None