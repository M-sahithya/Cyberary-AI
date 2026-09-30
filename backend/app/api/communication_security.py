"""
Cyberary-AI Communication Security Gateway API

Handles:
1. Incoming email/message analysis
2. Security decision persistence
3. Real-time WebSocket notifications
4. Audit logging
5. Human-in-the-loop review
"""

from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.postgres import get_db
from app.models.communication_security import CommunicationSecurityEvent
from app.schemas.communication_security import (
    CommunicationAnalyzeRequest,
    CommunicationReviewRequest,
    CommunicationSecurityResult,
)
from app.services.communication_security import analyze_communication
from app.services.communication_audit import (
    log_communication_security_event,
)
from app.api.websocket import (
    broadcast_communication_notification,
)


router = APIRouter(
    prefix="/api/communication",
    tags=["Communication Security"],
)


# ============================================================
# ANALYZE COMMUNICATION
# ============================================================

@router.post(
    "/analyze",
    response_model=CommunicationSecurityResult,
)
async def analyze_message(
    request: CommunicationAnalyzeRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Analyze an incoming email/message and apply
    deterministic security policy.
    """

    try:

        # ----------------------------------------------------
        # 1. SECURITY ANALYSIS
        # ----------------------------------------------------

        result = analyze_communication(
            sender=request.sender,
            recipient=request.recipient,
            subject=request.subject,
            body=request.body,
            urls=request.urls,
            attachments=request.attachments,
        )

        # ----------------------------------------------------
        # 2. CREATE DATABASE EVENT
        # ----------------------------------------------------

        event = CommunicationSecurityEvent(
            sender=request.sender,
            recipient=request.recipient,
            subject=request.subject,
            message_type=request.message_type.upper(),
            body=request.body,

            classification=result["classification"],
            risk_score=result["risk_score"],
            confidence=result["confidence"],
            severity=result["severity"],
            reason=result["reason"],

            sender_analysis=result["sender_analysis"],
            content_analysis=result["content_analysis"],
            url_analysis=result["url_analysis"],
            attachment_analysis=result["attachment_analysis"],

            threat_intelligence=result[
                "threat_intelligence"
            ],

            llm_analysis=result[
                "llm_analysis"
            ],

            policy_decision=result[
                "policy_decision"
            ],

            human_review_required=result[
                "human_review_required"
            ],

            notification_required=result[
                "notification_required"
            ],

            notification_sent=False,

            notification_level=result[
                "notification_level"
            ],

            urls=result["urls"],
            attachments=result["attachments"],
        )

        db.add(event)

        # ----------------------------------------------------
        # 3. FLUSH
        # ----------------------------------------------------
        # This generates the event ID without committing yet.

        await db.flush()

        event_id = str(event.id)

        # ----------------------------------------------------
        # 4. WEBSOCKET NOTIFICATION
        # ----------------------------------------------------

        notification_clients = 0

        if result["notification_required"]:

            notification_clients = (
                await broadcast_communication_notification(
                    event_id=event_id,
                    classification=result[
                        "classification"
                    ],
                    risk_score=result[
                        "risk_score"
                    ],
                    severity=result[
                        "severity"
                    ],
                    policy_decision=result[
                        "policy_decision"
                    ],
                    notification_level=result[
                        "notification_level"
                    ],
                    reason=result[
                        "reason"
                    ],
                    sender=request.sender,
                    subject=request.subject,
                    human_review_required=result[
                        "human_review_required"
                    ],
                )
            )

            # Notification was successfully delivered
            # if at least one WebSocket client received it.

            event.notification_sent = (
                notification_clients > 0
            )

        # ----------------------------------------------------
        # 5. AUDIT LOG
        # ----------------------------------------------------

        await log_communication_security_event(
            db=db,
            event_id=event_id,
            classification=result[
                "classification"
            ],
            risk_score=result[
                "risk_score"
            ],
            policy_decision=result[
                "policy_decision"
            ],
            notification_type=result[
                "notification_level"
            ],
            reason=result[
                "reason"
            ],
            metadata={
                "sender": request.sender,
                "recipient": request.recipient,
                "subject": request.subject,
                "message_type": request.message_type,
                "notification_clients": (
                    notification_clients
                ),
                "human_review_required": result[
                    "human_review_required"
                ],
            },
        )

        # ----------------------------------------------------
        # 6. COMMIT
        # ----------------------------------------------------

        await db.commit()

        # ----------------------------------------------------
        # 7. RESPONSE
        # ----------------------------------------------------

        return CommunicationSecurityResult(
            event_id=event.id,

            classification=result[
                "classification"
            ],

            risk_score=result[
                "risk_score"
            ],

            confidence=result[
                "confidence"
            ],

            severity=result[
                "severity"
            ],

            reason=result[
                "reason"
            ],

            recommended_action=result[
                "recommended_action"
            ],

            policy_decision=result[
                "policy_decision"
            ],

            human_review_required=result[
                "human_review_required"
            ],

            notification_required=result[
                "notification_required"
            ],

            notification_level=result[
                "notification_level"
            ],

            sender_analysis=result[
                "sender_analysis"
            ],

            content_analysis=result[
                "content_analysis"
            ],

            url_analysis=result[
                "url_analysis"
            ],

            attachment_analysis=result[
                "attachment_analysis"
            ],

            threat_intelligence=result[
                "threat_intelligence"
            ],

            llm_analysis=result[
                "llm_analysis"
            ],
        )

    except Exception as exc:

        await db.rollback()

        raise HTTPException(
            status_code=500,
            detail=(
                "Communication security analysis failed: "
                f"{str(exc)}"
            ),
        )


# ============================================================
# GET RECENT EVENTS
# ============================================================

@router.get("/events")
async def get_communication_events(
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
):
    """
    Return recent Communication Security Gateway events.
    """

    limit = max(1, min(limit, 200))

    result = await db.execute(
        select(CommunicationSecurityEvent)
        .order_by(
            CommunicationSecurityEvent.created_at.desc()
        )
        .limit(limit)
    )

    events = result.scalars().all()

    return {
        "count": len(events),
        "events": [
            {
                "event_id": str(event.id),
                "sender": event.sender,
                "recipient": event.recipient,
                "subject": event.subject,
                "classification": event.classification,
                "risk_score": event.risk_score,
                "confidence": event.confidence,
                "severity": event.severity,
                "policy_decision": event.policy_decision,
                "human_review_required": (
                    event.human_review_required
                ),
                "notification_required": (
                    event.notification_required
                ),
                "notification_sent": (
                    event.notification_sent
                ),
                "notification_level": (
                    event.notification_level
                ),
                "reason": event.reason,
                "created_at": (
                    event.created_at.isoformat()
                    if event.created_at
                    else None
                ),
            }
            for event in events
        ],
    }


# ============================================================
# GET SINGLE EVENT
# ============================================================

@router.get("/events/{event_id}")
async def get_communication_event(
    event_id: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Return detailed information about
    one Communication Security event.
    """

    result = await db.execute(
        select(CommunicationSecurityEvent).where(
            CommunicationSecurityEvent.id
            == event_id
        )
    )

    event = result.scalar_one_or_none()

    if event is None:

        raise HTTPException(
            status_code=404,
            detail="Communication security event not found",
        )

    return {
        "event_id": str(event.id),

        "sender": event.sender,
        "recipient": event.recipient,
        "subject": event.subject,
        "message_type": event.message_type,
        "body": event.body,

        "classification": event.classification,
        "risk_score": event.risk_score,
        "confidence": event.confidence,
        "severity": event.severity,
        "reason": event.reason,

        "sender_analysis": event.sender_analysis,
        "content_analysis": event.content_analysis,
        "url_analysis": event.url_analysis,
        "attachment_analysis": event.attachment_analysis,

        "threat_intelligence": (
            event.threat_intelligence
        ),

        "llm_analysis": event.llm_analysis,

        "policy_decision": (
            event.policy_decision
        ),

        "human_review_required": (
            event.human_review_required
        ),

        "reviewed": event.reviewed,
        "reviewed_by": event.reviewed_by,
        "review_comment": event.review_comment,

        "notification_required": (
            event.notification_required
        ),

        "notification_sent": (
            event.notification_sent
        ),

        "notification_level": (
            event.notification_level
        ),

        "urls": event.urls,
        "attachments": event.attachments,

        "created_at": (
            event.created_at.isoformat()
            if event.created_at
            else None
        ),

        "updated_at": (
            event.updated_at.isoformat()
            if event.updated_at
            else None
        ),
    }


# ============================================================
# HUMAN REVIEW
# ============================================================

@router.post("/events/{event_id}/review")
async def review_communication_event(
    event_id: str,
    request: CommunicationReviewRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Human-in-the-loop review.

    A security analyst can finally ALLOW or BLOCK
    a quarantined communication.
    """

    try:

        # ----------------------------------------------------
        # 1. FIND EVENT
        # ----------------------------------------------------

        result = await db.execute(
            select(CommunicationSecurityEvent).where(
                CommunicationSecurityEvent.id
                == event_id
            )
        )

        event = result.scalar_one_or_none()

        if event is None:

            raise HTTPException(
                status_code=404,
                detail=(
                    "Communication security event "
                    "not found"
                ),
            )

        # ----------------------------------------------------
        # 2. VALIDATE DECISION
        # ----------------------------------------------------

        decision = request.decision.upper()

        if decision not in {
            "ALLOW",
            "BLOCK",
        }:

            raise HTTPException(
                status_code=400,
                detail=(
                    "Review decision must be "
                    "ALLOW or BLOCK"
                ),
            )

        # ----------------------------------------------------
        # 3. UPDATE EVENT
        # ----------------------------------------------------

        event.policy_decision = decision

        event.reviewed = True

        event.reviewed_by = request.reviewed_by

        event.review_comment = request.comment

        event.human_review_required = False

        # ----------------------------------------------------
        # 4. AUDIT REVIEW
        # ----------------------------------------------------

        await log_communication_security_event(
            db=db,
            event_id=str(event.id),
            classification=event.classification,
            risk_score=event.risk_score,
            policy_decision=decision,
            notification_type=(
                "HUMAN_REVIEW"
            ),
            reason=(
                "Human analyst reviewed "
                "the quarantined communication."
            ),
            metadata={
                "reviewed_by": request.reviewed_by,
                "review_comment": request.comment,
                "previous_decision": (
                    event.policy_decision
                ),
            },
        )

        # ----------------------------------------------------
        # 5. COMMIT
        # ----------------------------------------------------

        await db.commit()

        return {
            "success": True,
            "event_id": str(event.id),
            "classification": event.classification,
            "risk_score": event.risk_score,
            "policy_decision": decision,
            "reviewed": True,
            "reviewed_by": request.reviewed_by,
            "review_comment": request.comment,
            "message": (
                "Communication security event "
                "review completed successfully."
            ),
        }

    except HTTPException:
        await db.rollback()
        raise

    except Exception as exc:

        await db.rollback()

        raise HTTPException(
            status_code=500,
            detail=(
                "Communication review failed: "
                f"{str(exc)}"
            ),
        )