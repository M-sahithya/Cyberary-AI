"""
Cyberary-AI WebSocket
Real-time security event streaming.

Supports:
1. Real security events from Ubuntu SSH collector
2. Demo events for dashboard testing
3. Communication Security Gateway notifications
"""

import asyncio
from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, WebSocket, WebSocketDisconnect


router = APIRouter(tags=["WebSocket"])


class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

        print(
            f"WebSocket connected. "
            f"Active clients: {len(self.active_connections)}"
        )

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

        print(
            f"WebSocket disconnected. "
            f"Active clients: {len(self.active_connections)}"
        )

    async def broadcast(self, message: dict) -> int:
        """
        Broadcast a message to all connected clients.

        Returns:
            Number of clients that successfully received the message.
        """

        disconnected = []
        sent_count = 0

        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
                sent_count += 1

            except Exception:
                disconnected.append(connection)

        for connection in disconnected:
            self.disconnect(connection)

        return sent_count

    async def send_personal(
        self,
        websocket: WebSocket,
        message: dict,
    ):
        try:
            await websocket.send_json(message)

        except Exception:
            self.disconnect(websocket)


manager = ConnectionManager()


# ============================================================
# REAL SECURITY EVENT BROADCAST
# ============================================================

async def broadcast_event(event: dict):
    """
    Broadcast real security events collected from Ubuntu SSH
    or other security sources.
    """

    if not event:
        return

    payload = dict(event)

    payload["type"] = "security_event"

    timestamp = payload.get("timestamp")

    if isinstance(timestamp, datetime):
        payload["timestamp"] = timestamp.isoformat()

    payload["source"] = payload.get(
        "source",
        "Ubuntu SSH Collector",
    )

    if "title" in payload and "event" not in payload:
        payload["event"] = payload["title"]
    elif "event" in payload and "title" not in payload:
        payload["title"] = payload["event"]
    elif "event_type" in payload and "event" not in payload:
        payload["event"] = payload.get("title") or payload["event_type"].replace("_", " ")
        payload["title"] = payload["event"]

    if "mitre_technique" in payload and "mitre" not in payload:
        payload["mitre"] = payload["mitre_technique"]

    await manager.broadcast(payload)

    print(
        "Real security event broadcast: "
        f"{payload.get('event_type', 'UNKNOWN')} | "
        f"{payload.get('severity', 'UNKNOWN')} | "
        f"{payload.get('attacker_ip', 'UNKNOWN')}"
    )


# ============================================================
# COMMUNICATION SECURITY NOTIFICATION
# ============================================================

async def broadcast_communication_notification(
    event_id: str,
    classification: str,
    risk_score: int,
    severity: str,
    policy_decision: str,
    notification_level: str,
    reason: str,
    sender: str,
    subject: str,
    human_review_required: bool,
) -> int:
    """
    Broadcast Communication Security Gateway notification.

    This is triggered only when the notification engine decides
    that a security notification is required.
    """

    payload = {
        "type": "communication_security_notification",
        "event_id": str(event_id),
        "classification": classification,
        "risk_score": risk_score,
        "severity": severity,
        "policy_decision": policy_decision,
        "notification_level": notification_level,
        "reason": reason,
        "sender": sender,
        "subject": subject,
        "human_review_required": human_review_required,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "Communication Security Gateway",
    }

    sent_count = await manager.broadcast(payload)

    print(
        "Communication security notification broadcast: "
        f"{classification} | "
        f"Risk={risk_score} | "
        f"Decision={policy_decision} | "
        f"Clients={sent_count}"
    )

    return sent_count


# ============================================================
# SECURITY EVENTS WEBSOCKET
# ============================================================

@router.websocket("/ws/security-events")
async def security_events_ws(websocket: WebSocket):

    await manager.connect(websocket)

    try:

        # Initial connection message
        await websocket.send_json(
            {
                "type": "connection",
                "message": (
                    "Connected to Cyberary-AI "
                    "Security Events Stream"
                ),
                "timestamp": datetime.now(
                    timezone.utc
                ).isoformat(),
                "lab_mode": True,
                "collector": "Ubuntu SSH",
            }
        )

        while True:

            try:

                data = await asyncio.wait_for(
                    websocket.receive_text(),
                    timeout=25.0,
                )

                if data == "ping":

                    await websocket.send_json(
                        {
                            "type": "pong",
                            "timestamp": datetime.now(
                                timezone.utc
                            ).isoformat(),
                        }
                    )

            except asyncio.TimeoutError:

                # Send heartbeat ping to maintain connection without injecting fake demo events
                try:
                    await websocket.send_json(
                        {
                            "type": "ping",
                            "timestamp": datetime.now(
                                timezone.utc
                            ).isoformat(),
                        }
                    )
                except Exception:
                    break

    except WebSocketDisconnect:

        manager.disconnect(websocket)

    except Exception as exc:

        print(
            f"WebSocket error: {exc}"
        )

        manager.disconnect(websocket)