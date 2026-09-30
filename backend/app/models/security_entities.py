"""
Cyber Security Models for Cyberary-AI

Defines database entities for:
- Assets
- Threats
- Honeypot Sessions
- Terminal Events
- Vulnerabilities
- CVEs
- MITRE Techniques
- Remediations
- Agent Tasks

Cyberary-AI Security Architecture:

    Telemetry
        ↓
    Detection
        ↓
    Risk Scoring
        ↓
    MITRE ATT&CK
        ↓
    Threat Database
        ↓
    WebSocket / Dashboard
        ↓
    Human Investigation
"""

import uuid

from datetime import datetime, timezone

from sqlalchemy import (
    Column,
    String,
    Boolean,
    DateTime,
    Float,
    Integer,
    ForeignKey,
    JSON,
    Text,
)

from sqlalchemy.orm import relationship

from app.database.postgres import Base


# ============================================================
# UUID GENERATOR
# ============================================================

def generate_uuid():
    """Generate a UUID string for database primary keys."""
    return str(uuid.uuid4())


# ============================================================
# ASSET
# ============================================================

class Asset(Base):
    """
    Authorized Asset in the Cyberary-AI lab environment.
    """

    __tablename__ = "assets"

    # --------------------------------------------------------
    # Identity
    # --------------------------------------------------------

    id = Column(
        String(36),
        primary_key=True,
        default=generate_uuid,
    )

    name = Column(
        String(100),
        unique=True,
        nullable=False,
        index=True,
    )

    ip_address = Column(
        String(45),
        nullable=False,
        index=True,
    )

    hostname = Column(
        String(255),
        nullable=True,
    )

    # --------------------------------------------------------
    # Environment
    # --------------------------------------------------------

    environment = Column(
        String(50),
        default="LAB",
        nullable=False,
    )

    asset_type = Column(
        String(50),
        default="linux",
        nullable=False,
    )

    importance = Column(
        String(20),
        default="HIGH",
        nullable=False,
    )

    status = Column(
        String(20),
        default="ONLINE",
        nullable=False,
    )

    is_authorized = Column(
        Boolean,
        default=True,
        nullable=False,
    )

    # --------------------------------------------------------
    # Risk / Scanning
    # --------------------------------------------------------

    last_scan = Column(
        DateTime,
        nullable=True,
    )

    risk_score = Column(
        Integer,
        default=0,
        nullable=False,
    )

    # --------------------------------------------------------
    # Timestamps
    # --------------------------------------------------------

    created_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    updated_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # --------------------------------------------------------
    # Relationships
    # --------------------------------------------------------

    vulnerabilities = relationship(
        "Vulnerability",
        back_populates="asset",
        cascade="all, delete-orphan",
    )

    threats = relationship(
        "Threat",
        back_populates="asset",
    )

    honeypot_sessions = relationship(
        "HoneypotSession",
        back_populates="asset",
    )


# ============================================================
# THREAT
# ============================================================

class Threat(Base):
    """
    Security threat detected across:

    - Honeypots
    - SSH authentication logs
    - Network telemetry
    - Vulnerability assessments
    - Security agents
    - Other Cyberary-AI detection sources

    Risk model:

        Detection
            ↓
        Severity
            ↓
        Risk Score
            ↓
        MITRE Mapping
            ↓
        Dashboard / Alert
    """

    __tablename__ = "threats"

    # --------------------------------------------------------
    # Identity
    # --------------------------------------------------------

    id = Column(
        String(36),
        primary_key=True,
        default=generate_uuid,
    )

    event_id = Column(
        String(50),
        unique=True,
        nullable=False,
        index=True,
    )

    # --------------------------------------------------------
    # Threat Information
    # --------------------------------------------------------

    title = Column(
        String(255),
        nullable=False,
    )

    source = Column(
        String(50),
        nullable=False,
    )

    severity = Column(
        String(20),
        default="MEDIUM",
        nullable=False,
    )

    status = Column(
        String(30),
        default="Active",
        nullable=False,
    )

    # --------------------------------------------------------
    # RISK SCORE
    # --------------------------------------------------------
    #
    # 0   = No calculated risk
    # 1-29 = LOW
    # 30-59 = MEDIUM
    # 60-89 = HIGH
    # 90-100 = CRITICAL
    #
    # Example SSH detection:
    #
    # 5+ failed attempts  -> 80
    # 10+ failed attempts -> 95
    #

    risk_score = Column(
        Float,
        default=0.0,
        nullable=False,
    )

    # --------------------------------------------------------
    # MITRE ATT&CK
    # --------------------------------------------------------

    mitre_technique = Column(
        String(50),
        nullable=True,
    )

    mitre_tactic = Column(
        String(50),
        nullable=True,
    )

    # --------------------------------------------------------
    # Detection Intelligence
    # --------------------------------------------------------

    intent = Column(
        String(255),
        nullable=True,
    )

    impact = Column(
        Text,
        nullable=True,
    )

    confidence = Column(
        Float,
        default=0.85,
        nullable=False,
    )

    # --------------------------------------------------------
    # Raw Evidence
    # --------------------------------------------------------

    raw_payload = Column(
        Text,
        nullable=True,
    )

    # --------------------------------------------------------
    # Asset Relationship
    # --------------------------------------------------------

    asset_id = Column(
        String(36),
        ForeignKey(
            "assets.id",
            ondelete="SET NULL",
        ),
        nullable=True,
    )

    # --------------------------------------------------------
    # Timestamp
    # --------------------------------------------------------

    timestamp = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    # --------------------------------------------------------
    # Relationships
    # --------------------------------------------------------

    asset = relationship(
        "Asset",
        back_populates="threats",
    )


# ============================================================
# HONEYPOT SESSION
# ============================================================

class HoneypotSession(Base):
    """
    Interactive honeypot session.

    Records attacker interaction with the authorized
    Cyberary-AI lab honeypot.
    """

    __tablename__ = "honeypot_sessions"

    id = Column(
        String(36),
        primary_key=True,
        default=generate_uuid,
    )

    session_code = Column(
        String(50),
        unique=True,
        nullable=False,
        index=True,
    )

    attacker_ip = Column(
        String(45),
        default="10.0.1.105",
        nullable=False,
    )

    username = Column(
        String(100),
        default="root",
        nullable=False,
    )

    status = Column(
        String(20),
        default="ACTIVE",
        nullable=False,
    )

    protocol = Column(
        String(20),
        default="SSH",
        nullable=False,
    )

    start_time = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    end_time = Column(
        DateTime,
        nullable=True,
    )

    threat_level = Column(
        String(20),
        default="HIGH",
        nullable=False,
    )

    command_count = Column(
        Integer,
        default=0,
        nullable=False,
    )

    session_metadata = Column(
        JSON,
        nullable=True,
    )

    asset_id = Column(
        String(36),
        ForeignKey(
            "assets.id",
            ondelete="SET NULL",
        ),
        nullable=True,
    )

    # --------------------------------------------------------
    # Relationships
    # --------------------------------------------------------

    asset = relationship(
        "Asset",
        back_populates="honeypot_sessions",
    )

    terminal_events = relationship(
        "TerminalEvent",
        back_populates="session",
        cascade="all, delete-orphan",
    )


# ============================================================
# TERMINAL EVENT
# ============================================================

class TerminalEvent(Base):
    """
    Raw terminal command sequences executed inside
    Cyberary-AI honeypot sessions.
    """

    __tablename__ = "terminal_events"

    id = Column(
        String(36),
        primary_key=True,
        default=generate_uuid,
    )

    session_id = Column(
        String(36),
        ForeignKey(
            "honeypot_sessions.id",
            ondelete="CASCADE",
        ),
        nullable=False,
    )

    command = Column(
        Text,
        nullable=False,
    )

    response = Column(
        Text,
        nullable=True,
    )

    intent = Column(
        String(255),
        nullable=True,
    )

    mitre_technique = Column(
        String(50),
        nullable=True,
    )

    mitre_tactic = Column(
        String(50),
        nullable=True,
    )

    severity = Column(
        String(20),
        default="MEDIUM",
        nullable=False,
    )

    event_metadata = Column(
        JSON,
        nullable=True,
    )

    timestamp = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # --------------------------------------------------------
    # Relationships
    # --------------------------------------------------------

    session = relationship(
        "HoneypotSession",
        back_populates="terminal_events",
    )


# ============================================================
# VULNERABILITY
# ============================================================

class Vulnerability(Base):
    """
    Vulnerability discovered during authorized
    offensive security assessments.
    """

    __tablename__ = "vulnerabilities"

    id = Column(
        String(36),
        primary_key=True,
        default=generate_uuid,
    )

    finding_id = Column(
        String(50),
        unique=True,
        nullable=False,
        index=True,
    )

    asset_id = Column(
        String(36),
        ForeignKey(
            "assets.id",
            ondelete="CASCADE",
        ),
        nullable=False,
    )

    title = Column(
        String(255),
        nullable=False,
    )

    description = Column(
        Text,
        nullable=True,
    )

    cve_id = Column(
        String(50),
        nullable=True,
        index=True,
    )

    cvss_score = Column(
        Float,
        default=7.5,
        nullable=False,
    )

    severity = Column(
        String(20),
        default="HIGH",
        nullable=False,
    )

    affected_service = Column(
        String(100),
        nullable=True,
    )

    confidence = Column(
        Float,
        default=0.9,
        nullable=False,
    )

    status = Column(
        String(20),
        default="OPEN",
        nullable=False,
    )

    evidence = Column(
        Text,
        nullable=True,
    )

    discovered_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # --------------------------------------------------------
    # Relationships
    # --------------------------------------------------------

    asset = relationship(
        "Asset",
        back_populates="vulnerabilities",
    )

    remediations = relationship(
        "Remediation",
        back_populates="vulnerability",
    )


# ============================================================
# REMEDIATION
# ============================================================

class Remediation(Base):
    """
    AI-generated remediation recommendation.

    All remediation actions require human approval.
    """

    __tablename__ = "remediations"

    id = Column(
        String(36),
        primary_key=True,
        default=generate_uuid,
    )

    remediation_code = Column(
        String(50),
        unique=True,
        nullable=False,
        index=True,
    )

    vulnerability_id = Column(
        String(36),
        ForeignKey(
            "vulnerabilities.id",
            ondelete="CASCADE",
        ),
        nullable=True,
    )

    issue = Column(
        String(255),
        nullable=False,
    )

    severity = Column(
        String(20),
        default="HIGH",
        nullable=False,
    )

    risk_score = Column(
        Integer,
        default=75,
        nullable=False,
    )

    recommended_fix = Column(
        Text,
        nullable=False,
    )

    proposed_command = Column(
        Text,
        nullable=True,
    )

    expected_result = Column(
        Text,
        nullable=True,
    )

    verification_step = Column(
        Text,
        nullable=True,
    )

    rollback_plan = Column(
        Text,
        nullable=True,
    )

    status = Column(
        String(20),
        default="PENDING",
        nullable=False,
    )

    reviewed_by = Column(
        String(100),
        nullable=True,
    )

    reviewed_at = Column(
        DateTime,
        nullable=True,
    )

    created_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # --------------------------------------------------------
    # Relationships
    # --------------------------------------------------------

    vulnerability = relationship(
        "Vulnerability",
        back_populates="remediations",
    )


# ============================================================
# MITRE ATT&CK TECHNIQUE
# ============================================================

class MitreTechnique(Base):
    """
    MITRE ATT&CK technique catalog.

    Example:

        T1110
        T1110.001
        T1059.004
        T1046
    """

    __tablename__ = "mitre_techniques"

    id = Column(
        String(36),
        primary_key=True,
        default=generate_uuid,
    )

    technique_id = Column(
        String(50),
        unique=True,
        nullable=False,
        index=True,
    )

    name = Column(
        String(255),
        nullable=False,
    )

    tactic = Column(
        String(100),
        nullable=False,
        index=True,
    )

    description = Column(
        Text,
        nullable=True,
    )

    detection_count = Column(
        Integer,
        default=0,
        nullable=False,
    )

    confidence = Column(
        Float,
        default=0.88,
        nullable=False,
    )

    created_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


# ============================================================
# AGENT TASK
# ============================================================

class AgentTask(Base):
    """
    Multi-Agent Cyberary-AI execution tracker.

    Possible agents:

        - Offensive AI Agent
        - Honeypot Agent
        - Threat Intelligence Agent
        - CVE Agent
        - Remediation Agent
    """

    __tablename__ = "agent_tasks"

    id = Column(
        String(36),
        primary_key=True,
        default=generate_uuid,
    )

    agent_name = Column(
        String(100),
        nullable=False,
    )

    task_type = Column(
        String(100),
        nullable=False,
    )

    status = Column(
        String(20),
        default="IDLE",
        nullable=False,
    )

    last_run = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    result_summary = Column(
        Text,
        nullable=True,
    )

    logs = Column(
        JSON,
        nullable=True,
    )


# ============================================================
# RESEARCH EVALUATION RUN (Future Work Benchmarking & Evidence)
# ============================================================

class ResearchEvaluationRun(Base):
    """
    Empirical research evaluation runs for the two integrated papers:
    1. 'LLM Agents can Autonomously Exploit One-day Vulnerabilities' (Richard Fang et al., 2024)
    2. 'LLM in the Shell: Generative Honeypots' (shelLM, Muris Sladic et al., 2024)
    """

    __tablename__ = "research_evaluation_runs"

    id = Column(
        String(36),
        primary_key=True,
        default=generate_uuid,
    )

    run_code = Column(
        String(50),
        unique=True,
        nullable=False,
        index=True,
    )

    eval_type = Column(
        String(50),
        nullable=False,
        index=True,
    )

    target = Column(
        String(255),
        nullable=False,
    )

    status = Column(
        String(30),
        default="RUNNING",
        nullable=False,
        index=True,
    )

    configuration = Column(
        JSON,
        default=dict,
        nullable=False,
    )

    metrics = Column(
        JSON,
        default=dict,
        nullable=False,
    )

    results = Column(
        JSON,
        default=dict,
        nullable=False,
    )

    summary = Column(
        Text,
        nullable=True,
    )

    token_usage = Column(
        JSON,
        default=dict,
        nullable=True,
    )

    error_message = Column(
        Text,
        nullable=True,
    )

    started_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    completed_at = Column(
        DateTime,
        nullable=True,
    )