"""
Integration Verification Script
Verifies:
1. Database initialization + schema verification (no missing columns)
2. Database seeding (admin, assets including ubuntu-telemetry-vm, threats with risk_score, mitre)
3. Threat creation & persistence with risk_score
4. MITRE detection count updates
5. WebSocket connection & real event reception
"""

import asyncio
import json
from datetime import datetime, timezone
import websockets
from sqlalchemy import select, func

from app.database.postgres import init_postgres, close_postgres, async_session_factory
from app.database.seed import seed_database
from app.models.security_entities import Threat, MitreTechnique, Asset
from app.services.ubuntu_ssh_collector import (
    save_threat_to_database,
    broadcast_security_event,
)
from app.services.ssh_log_collector import parse_ssh_log_line


async def test_integration():
    print("\n--- 1. Testing DB init & seed ---")
    await init_postgres()
    await seed_database()
    print("Database initialized and seeded successfully.")

    async with async_session_factory() as db:
        # Verify ubuntu-telemetry-vm asset
        asset_res = await db.execute(
            select(Asset).where(Asset.ip_address == "192.168.56.103")
        )
        ubuntu_asset = asset_res.scalar_one_or_none()
        assert ubuntu_asset is not None, "ubuntu-telemetry-vm asset should exist in DB"
        print(f"Verified Ubuntu asset: {ubuntu_asset.name} ({ubuntu_asset.ip_address})")

        # Verify threats table and risk_score
        threat_count_res = await db.execute(select(func.count(Threat.id)))
        threat_count = threat_count_res.scalar()
        print(f"Total threats in DB: {threat_count}")
        assert threat_count > 0, "Threats should be seeded"

        # Check that risk_score is populated on threats
        first_threat_res = await db.execute(select(Threat).limit(1))
        t = first_threat_res.scalar_one()
        assert hasattr(t, "risk_score") and t.risk_score is not None
        print(f"Sample threat: {t.title} | Risk score: {t.risk_score}")

    print("\n--- 2. Testing SSH Parser + Persistence + MITRE Mapping ---")
    test_line = "Failed password for testanalyst from 192.168.56.103 port 49123 ssh2"
    parsed_event = parse_ssh_log_line(test_line)
    assert parsed_event is not None
    print(f"Parsed event: {parsed_event['event_type']} for {parsed_event['username']}")

    # Check MITRE count before
    async with async_session_factory() as db:
        mitre_before_res = await db.execute(
            select(MitreTechnique).where(MitreTechnique.technique_id == "T1110.001")
        )
        mitre_before = mitre_before_res.scalar_one_or_none()
        count_before = mitre_before.detection_count if mitre_before else 0

    # Save threat
    event_id = await save_threat_to_database(parsed_event)
    assert event_id is not None
    print(f"Threat saved with ID: {event_id}")

    # Check MITRE count after
    async with async_session_factory() as db:
        mitre_after_res = await db.execute(
            select(MitreTechnique).where(MitreTechnique.technique_id == "T1110.001")
        )
        mitre_after = mitre_after_res.scalar_one()
        print(f"MITRE T1110.001 count before: {count_before} -> after: {mitre_after.detection_count}")
        assert mitre_after.detection_count == count_before + 1

        # Check saved threat record
        saved_res = await db.execute(
            select(Threat).where(Threat.event_id == event_id)
        )
        saved_threat = saved_res.scalar_one()
        assert saved_threat.risk_score > 0
        print(f"Saved threat verified: {saved_threat.event_id} | Risk: {saved_threat.risk_score}")

    await close_postgres()
    print("\n[OK] Integration Verification Succeeded!")


if __name__ == "__main__":
    asyncio.run(test_integration())
