# 🛡️ CYBERARY-AI: Autonomous Cyber Defense & Offensive Operations Platform

> **A Next-Generation, Dual-Faceted Autonomous Cybersecurity Platform Connecting Ethical AI Exploitation, Dynamic Generative Honeypots, Continuous Threat Ingress Telemetry, NVD 2.0 CVE Intelligence, MITRE ATT&CK Mapping, and Human-in-the-Loop Automated Remediation.**
> 
> *Strictly Designed and Guarded for Authorized Lab & Cyber-Range Environments.*

---

## 📑 Table of Contents

1. [Executive Summary & Problem Statement](#-executive-summary--problem-statement)
2. [Research Grounding & Scientific Innovations](#-research-grounding--scientific-innovations)
3. [Platform Architecture & System Topology](#-platform-architecture--system-topology)
4. [Functional Modules Breakdown](#-functional-modules-breakdown)
   - [1. Security Operations Center (SOC) Live Dashboard](#1-security-operations-center-soc-live-dashboard)
   - [2. Interactive Authentication & Operator Enlistment (Login & Register)](#2-interactive-authentication--operator-enlistment-login--register)
   - [3. Threat Intelligence & Real-Time Telemetry Feed](#3-threat-intelligence--real-time-telemetry-feed)
   - [4. Dynamic AI Honeypots (shelLM Generative Core)](#4-dynamic-ai-honeypots-shellm-generative-core)
   - [5. Vulnerability Assessment & Ethical Exploit Scanner](#5-vulnerability-assessment--ethical-exploit-scanner)
   - [6. NIST NVD 2.0 CVE Intelligence Catalog & Dossier](#6-nist-nvd-20-cve-intelligence-catalog--dossier)
   - [7. MITRE ATT&CK Matrix Navigator](#7-mitre-attck-matrix-navigator)
   - [8. Autonomous Remediation & Human-in-the-Loop Patch Engine](#8-autonomous-remediation--human-in-the-loop-patch-engine)
   - [9. Authorized Lab Assets & Inventory Management](#9-authorized-lab-assets--inventory-management)
   - [10. Autonomous AI Agents Orchestrator (Richard Fang et al.)](#10-autonomous-ai-agents-orchestrator-richard-fang-et-al)
   - [11. Empirical Evaluation & Verification Benchmark Suite](#11-empirical-evaluation--verification-benchmark-suite)
   - [12. Immutable Forensic Audit Trail](#12-immutable-forensic-audit-trail)
   - [13. AI Communication Security Gateway (Phishing & Fraud Detection)](#13-ai-communication-security-gateway-phishing--fraud-detection)
   - [14. System Configuration & LLM Inference Engine](#14-system-configuration--llm-inference-engine)
5. [Technology Stack](#-technology-stack)
6. [Complete REST API Reference](#-complete-rest-api-reference)
7. [Installation, Setup & Deployment Guide](#-installation-setup--deployment-guide)
8. [Database Schema & Entity Models](#-database-schema--entity-models)
9. [Verification, Testing & Telemetry Scripts](#-verification-testing--telemetry-scripts)
10. [Safety Constraints & Lab Isolation Policies](#-safety-constraints--lab-isolation-policies)

---

## 🎯 Executive Summary & Problem Statement

Modern cybersecurity operations centers face an unsustainable crisis:
- **Alert Saturation:** Security teams receive tens of thousands of security alerts daily, with over 75% being false positives or non-actionable noise.
- **Critical Latency (MTTD & MTTR):** Traditional manual triaging, CVE cross-referencing, attack reproduction, and patch generation take days to weeks—leaving networks vulnerable during the zero-day and one-day exploit window.
- **Fragmented Tooling:** Disconnected scanners, honeypots, and SIEMs do not share unified contextual awareness.
- **Shortage of Skilled Defensive Engineers:** Junior analysts struggle to infer attacker intent and derive safe remediation scripts without breaking production services.

### The Cyberary-AI Solution
Cyberary-AI closes the entire security loop into an autonomous, intelligence-driven feedback cycle:

```
[Target Lab Asset] ────► [Offensive Subagents] ────► [Vulnerability Scanner]
        ▲                                                      │
        │                                                      ▼
[Automated Patching] ◄── [Human-in-the-Loop] ◄── [Remediation Engine]
        ▲                                                      │
        │                                                      ▼
[Dynamic Honeypot] ────► [Stateful LLM Shell] ────► [MITRE ATT&CK & CVE NVD]
```

Every threat captured by the generative honeypot or discovered by ethical scans is automatically classified, mapped to MITRE tactics, contextualized with CVSS metrics, assigned automated patches, and staged for one-click human verification and rollback.

---

## 🔬 Research Grounding & Scientific Innovations

Cyberary-AI integrates seminal breakthroughs from recent peer-reviewed security and AI literature:

1. **Richard Fang et al. (2024) — *Autonomous One-Day Exploit Planning*:**
   - Implements multi-vector autonomous planning with hierarchical subagents.
   - Accepts structured CVE descriptions from the NIST National Vulnerability Database to autonomously generate ethical exploit proof-of-concepts inside sandboxed lab environments.
2. **shelLM (2024) — *Generative AI Honeypot Core*:**
   - Moves beyond static low-interaction honeypots (like basic Cowrie) by employing LLM-powered interactive command synthesis.
   - Simulates a stateful Linux kernel, maintains virtual filesystem trees (`/etc/shadow`, `/tmp`, `/var/log`), detects attacker intent, and drops synthetic canary breadcrumbs.
3. **ACIDRain (2024) — *Database Concurrency & Transactional Verification*:**
   - Incorporates race-condition and transaction isolation testing against web application databases to detect double-spend and access token race conditions.
4. **Communication Security Gateway:**
   - Employs dual-stage natural language risk heuristics and heuristic payload extraction to neutralize spear-phishing, business email compromise (BEC), and malicious invoice links.

---

## 🏛️ Platform Architecture & System Topology

Cyberary-AI is built on an enterprise multi-tier architecture designed for isolated deployment:

```
┌────────────────────────────────────────────────────────────────────────┐
│                   CYBERARY-AI SOC FRONTEND (React 18 + Vite)           │
│  - Neon Glassmorphism Cyber HUD       - Real-time WebSocket Feed      │
│  - 13 Specialized Modules             - Interactive Attack Timeline    │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ REST APIs + WSS (JWT Authenticated)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                     FASTAPI BACKEND APIS & SERVICES                    │
│  ├── /api/auth              - JWT issuance, PBKDF2/Bcrypt, RBAC        │
│  ├── /api/dashboard         - Live telemetry aggregation & VM health   │
│  ├── /api/threats           - Real-time intrusion stream ingestion     │
│  ├── /api/honeypot          - Stateful shelLM decoy simulation         │
│  ├── /api/vulnerabilities   - Ethical discovery & risk scoring         │
│  ├── /api/cve               - NIST NVD 2.0 API connector & catalog     │
│  ├── /api/mitre             - ATT&CK tactic/technique navigator        │
│  ├── /api/remediation       - Patch synthesis, approval & rollback     │
│  ├── /api/assets            - Authorized target inventory (RFC 1918)   │
│  ├── /api/agents            - Multi-agent orchestrator & planners      │
│  ├── /api/evaluation        - Scientific benchmark matrix              │
│  ├── /api/audit-logs        - Immutable SHA-256 logged forensic ledger │
│  └── /api/communication-sec - Phishing & email threat detector         │
└──────────────┬─────────────────────────┬───────────────────────────────┘
               │                         │
               ▼                         ▼
┌───────────────────────────────┐ ┌──────────────────────────────────────┐
│       DATA PERSISTENCE        │ │       AI INFERENCE & AGENTS          │
│ - SQLite / PostgreSQL (Async) │ │ - Local Private Ollama (Llama 3)     │
│ - Audit Ledger (Append-only)  │ │ - OpenAI / Anthropic Compatible APIs │
│ - MongoDB (Raw Cowrie Logs)   │ │ - LangChain Execution Orchestration  │
└───────────────────────────────┘ └──────────────────────────────────────┘
```

---

## 📦 Functional Modules Breakdown

### 1. Security Operations Center (SOC) Live Dashboard
- **Unified Defensive Posture:** Visualizes overall risk score, active threats, open vulnerabilities, and active honeypot engagements.
- **Live SSH Telemetry Layer:** Direct background collector tracking live telemetry from authorized Linux/Ubuntu lab instances (active SSH sessions, CPU/RAM utilization, auth failure rates).
- **Interactive Graphs:** Trend charts detailing attack distribution by MITRE tactic and threat severity over time.
- **Telemetry Synchronization:** Instant manual and WebSocket-driven telemetry sync buttons.

### 2. Interactive Authentication & Operator Enlistment (Login & Register)
- **High-Aesthetic Cyber HUD:** Dark mode glassmorphism with dynamic glowing borders, animated grid overlays, and status indicators.
- **Terminal Authentication (Login):**
  - Live pre-configured demo credentials (`admin` / `CyberaryAdmin123!`) with a single-click autofill button.
  - Password reveal toggle and client-side credential verification.
- **Operator Enlistment (Register):**
  - Real-time client-side password strength meter (Weak, Fair, Good, Strong) based on entropy.
  - Operational role persona selection: *SOC Analyst*, *Offensive Operator*, *Remediation Lead*, and *Compliance Auditor*.
  - Strict lab email domain validator accepting both standard enterprise and isolated lab formats (`.local`).
  - Single-click **Demo Autofill** generating immediate test credentials.

### 3. Threat Intelligence & Real-Time Telemetry Feed
- **Live Event Stream:** Categorizes captured threats with timestamps, ingress source, severity ratings, MITRE codes, and raw captured payloads.
- **Simulate Intrusion Event:** Direct button to inject ethical simulated intrusion sequences into the database and verify alerts.
- **JSON Telemetry Export:** Instant download of captured intrusion intelligence.
- **Modal Deep-Dive:** Comprehensive threat dossier detailing attacker intent, potential operational impact, and captured exploit strings.

### 4. Dynamic AI Honeypots (shelLM Generative Core)
- **Stateful Decoy Environments:** Tracks interactive attacker sessions across custom hostnames, usernames, and working directories.
- **Attack Arsenal Quick-Run Pills:** Direct 1-click execution for common reconnaissance commands (`whoami`, `uname -a`, `id`, `cat /etc/shadow`, `sudo -l`, `ls -la /tmp`).
- **Research Metrics Bar:** Real-time suspicion meter, attacker classification (human vs. automated scanner), and canary decoys planted.
- **Session Reset & Trace Export:** Reset sessions to clean baseline states or export the complete command timeline as JSON.

### 5. Vulnerability Assessment & Ethical Exploit Scanner
- **Offensive AI Agent Console:** Triggers automated scans against allowlisted lab targets (`lab-server-01`, `lab-server-02`, `lab-honeypot-01`).
- **Interactive Findings Matrix:** Displays Finding ID, asset name, title, CVE ID, CVSS score, severity, affected port, and remediation status.
- **Direct Row Actions:**
  - `Inspect`: View comprehensive vulnerability dossier.
  - `Remediate`: Direct jump to the remediation console to generate or execute fixes.
- **Severity Filters & Export:** Quick filter tabs (Critical, High, Medium, Remediated) and JSON report export.

### 6. NIST NVD 2.0 CVE Intelligence Catalog & Dossier
- **Real-Time NVD Connector:** Queries official NIST NVD API 2.0 with automatic offline fallback caching.
- **Quick Lookup Pills:** 1-click buttons for historic and modern benchmark vulnerabilities:
  - `CVE-2024-6387` (OpenSSH Remote Code Execution - regreSSHion)
  - `CVE-2023-38408` (OpenSSH PKCS#11 Provider RCE)
  - `CVE-2021-44228` (Apache Log4j Log4Shell)
  - `CVE-2024-3094` (XZ Utils Embedded Backdoor)
- **Detailed Vulnerability Dossier:** CVSS v3.1 vectors, exploitability metrics, affected software configurations (CPE), and JSON dossier download.

### 7. MITRE ATT&CK Matrix Navigator
- **Enterprise Matrix Visualizer:** Filter across standard tactics (*Reconnaissance*, *Initial Access*, *Execution*, *Persistence*, *Privilege Escalation*, *Defense Evasion*, *Credential Access*, *Lateral Movement*).
- **Technique Deep-Dive:** View technique ID, detection event count, adversary procedure examples, and suggested mitigation guidelines.

### 8. Autonomous Remediation & Human-in-the-Loop Patch Engine
- **Zero Blind-Patch Policy:** Every patch requires affirmative review and approval by an authorized analyst before lab execution.
- **Three-Stage Workflow:** `PENDING REVIEW` ──► `APPROVED` ──► `EXECUTED (LAB PATCH)` ──► `VERIFIED`.
- **Automated Rollback Safeguard:** Every remediation plan includes a cryptographically paired rollback script.

### 9. Authorized Lab Assets & Inventory Management
- **Target Allowlist Enforcement:** Strict RFC 1918 private IPv4 validation (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) to guarantee that offensive actions can never target external public networks.
- **Live Node Ping Probe:** Interactive connectivity test probing asset reachability with latency feedback.
- **Asset Registration Modal:** Includes a 1-click **Autofill Sample Target** button for rapid lab provisioning.

### 10. Autonomous AI Agents Orchestrator (Richard Fang et al.)
- **Subagent Coordination Engine:** Coordinates four specialized agent personas:
  - *Offensive Assessment Agent*
  - *Honeypot Decoy Specialist*
  - *Threat Intelligence Classifier*
  - *Remediation Engineer*
- **Hierarchical Exploit Planner:** Accepts CVE parameters, generates exploitation graphs, and validates race conditions via ACIDRain concurrency testing.

### 11. Empirical Evaluation & Verification Benchmark Suite
- **Scientific Evidence Matrix:** Benchmark verification table comparing model performance across benchmark CVEs.
- **Execution Run Trigger:** Test benchmark suites with optional ACIDRain concurrency verification.

### 12. Immutable Forensic Audit Trail
- **Append-Only Event Ledger:** Cryptographically logged records of all logins, user registrations, patch approvals, rejections, and target enrolments.
- **Forensic Inspector Modal:** View raw JSON payloads, client IP addresses, and exact timestamps.
- **Export Audit Trail:** Download full audit trail as JSON.

### 13. AI Communication Security Gateway
- **Dual-Model Natural Language Analysis:** Analyzes emails, SMS, and instant messages for spear-phishing, social engineering, spoofing, and malicious links.
- **Quick Preset Test Arsenal:** 1-click test buttons for *CEO Wire Fraud*, *Credential Harvester*, and *Legitimate IT Maintenance*.
- **Risk Indicator Extraction:** Flags urgent payment demands, artificial pressure, mismatched reply-to headers, and suspicious URLs.

### 14. System Configuration & LLM Inference Engine
- **Inference Engine Switching:** Seamlessly switch between local private Ollama (`llama3`, `mistral`) and cloud-compatible REST endpoints.
- **Connectivity Testing:** Live "Test Connection" probe measuring engine latency.
- **Configuration Export & Reset:** Export SOC configuration as JSON or reset to recommended lab defaults.

---

## 🛠️ Technology Stack

| Component | Technology | Rationale |
|---|---|---|
| **Frontend Framework** | React 18, Vite | Lightning-fast HMR and optimized component rendering |
| **Styling & Theme** | Tailwind CSS v3, Vanilla CSS Custom Tokens | Cyan/purple cyberpunk HUD, neon glows, glassmorphism |
| **Icons & UI** | Lucide React | Clean, scalable vector cybersecurity iconography |
| **Backend Framework** | Python 3.11+, FastAPI | High-throughput asynchronous endpoints with native OpenAPI docs |
| **ORM & Database** | SQLAlchemy (AsyncIO), SQLite / PostgreSQL | Robust ACID compliance and async database sessions |
| **Data Validation** | Pydantic v2 | Strict schema validation and serialization |
| **Security & Auth** | Passlib (PBKDF2/Bcrypt), PyJWT | Industry-standard JWT tokens with role claims |
| **Network & Telemetry** | AsyncSSH, WebSockets | Live background telemetry streaming from lab nodes |
| **Intelligence APIs** | NIST NVD API 2.0 | Authoritative CVE and CVSS v3.1 metadata |

---

## 🔌 Complete REST API Reference

### Authentication & Identity (`/api/auth`)
| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/auth/register` | Register a new operator account (assigns default VIEWER role) |
| `POST` | `/api/auth/login` | Authenticate with username and password, returns JWT token |
| `GET` | `/api/auth/me` | Retrieve the authenticated operator's profile and active roles |

### Dashboard & Telemetry (`/api/dashboard`)
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/dashboard/summary` | Aggregate metrics (threats, vulns, honeypot sessions, risk score) |
| `GET` | `/api/dashboard/ssh-status` | Status and host information for live VM telemetry collector |

### Threat Intelligence (`/api/threats`)
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/threats` | List recorded security events (supports `severity` and `status` filters) |
| `GET` | `/api/threats/{event_id}` | Retrieve full threat dossier and captured raw payloads |

### Dynamic AI Honeypot (`/api/honeypot`)
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/honeypot/sessions` | List active attacker sessions |
| `GET` | `/api/honeypot/sessions/{session_id}` | Detailed session metadata, suspicion score, and command timeline |
| `POST` | `/api/honeypot/sessions/{session_id}/reset` | Reset a decoy session to clean initial baseline state |
| `POST` | `/api/honeypot/simulate-command` | Simulate attacker command execution in the generative shell |

### Vulnerability Assessment (`/api/vulnerabilities`)
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/vulnerabilities` | List open vulnerability findings across lab targets |
| `POST` | `/api/vulnerabilities/scan` | Trigger offensive agent assessment against an authorized target |

### CVE Intelligence (`/api/cve`)
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/cve` | List indexed CVE records in local database cache |
| `GET` | `/api/cve/{cve_id}` | Fetch detailed NIST NVD 2.0 metadata and CVSS vectors |

### MITRE ATT&CK (`/api/mitre`)
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/mitre/tactics` | List all MITRE ATT&CK tactics |
| `GET` | `/api/mitre/techniques` | List techniques with detection event counts |
| `GET` | `/api/mitre/techniques/{technique_id}` | Inspect technique details, mitigations, and adversary procedures |

### Remediation Engine (`/api/remediation`)
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/remediation` | List pending, approved, and executed remediation plans |
| `POST` | `/api/remediation/{remediation_code}/approve` | Approve a remediation plan for deployment |
| `POST` | `/api/remediation/{remediation_code}/reject` | Reject a remediation recommendation |
| `POST` | `/api/remediation/{remediation_code}/execute` | Execute an approved patch inside the target lab environment |

### Lab Asset Inventory (`/api/assets`)
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/assets` | List registered authorized lab targets |
| `POST` | `/api/assets` | Register a new target (strictly enforces private IPv4 ranges) |

### AI Agents & Autonomous Planning (`/api/agents`)
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/agents` | Status and last task info for all orchestrated subagents |
| `POST` | `/api/agents/{agent_id}/run` | Manually trigger an agent routine cycle |
| `POST` | `/api/agents/offensive/autonomous-plan` | Execute autonomous exploit plan with subagents and concurrency checks |

### Forensic Audit Ledger (`/api/audit-logs`)
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/audit-logs` | Retrieve immutable audit log entries (filterable by `action`) |

### Communication Security (`/api/communication-security`)
| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/communication-security/analyze` | Submit email or message for security classification and intent extraction |

### Engine Settings (`/api/settings`)
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/settings` | Retrieve active LLM configuration and lab mode status |
| `PUT` | `/api/settings` | Update LLM inference provider, model identifier, or lab mode |

---

## 🚀 Installation, Setup & Deployment Guide

### Prerequisites
- **Node.js:** v18.0+ & npm
- **Python:** 3.11 or higher
- **Git**
- *(Optional)* **Docker & Docker Compose**

---

### Method A: Local Native Development (Recommended for Testing)

#### 1. Backend Setup
```bash
cd backend

# Create and activate Python virtual environment
python -m venv venv
# On Windows:
.\venv\Scripts\Activate.ps1
# On Linux/macOS:
# source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run initial database migrations and seed default credentials
python -m app.database.seed

# Start the FastAPI server
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

The backend API will start at `http://localhost:8000`.
- Interactive Swagger API Documentation: `http://localhost:8000/docs`
- Redoc Documentation: `http://localhost:8000/redoc`

#### 2. Frontend Setup
```bash
cd frontend

# Install npm dependencies
npm install

# Start the Vite development server
npm run dev
```

The frontend dashboard will be available at `http://localhost:5173`.

---

### Method B: Docker Compose Deployment

To launch the complete containerized stack (FastAPI Backend, React Frontend, PostgreSQL, and Decoy Listener):

```bash
# Clone and enter directory
git clone https://github.com/your-org/cyberary-ai.git
cd cyberary-ai

# Copy environment variables
cp .env.example .env

# Build and start all microservices
docker compose up -d --build

# Verify running containers
docker compose ps
```

---

## 🔑 Default Credentials

| Role | Username | Password | Access Level |
|---|---|---|---|
| **Administrator** | `admin` | `CyberaryAdmin123!` | Full control, patch execution, agent triggers |
| **SOC Analyst** | `analyst` | `CyberaryAnalyst123!` | Threat monitoring, scan execution, patch review |
| **Auditor / Viewer** | Self-registered via `/register` | User-defined (min 8 chars) | Read-only access to audit logs and telemetry |

> 💡 *Both Login (`/login`) and Register (`/register`) pages include single-click **Demo Autofill** buttons for instant testing.*

---

## 🧪 Verification, Testing & Telemetry Scripts

The repository includes dedicated verification scripts in the `backend/` directory:

1. **Verify Live REST APIs:**
   ```bash
   python backend/verify_live_apis.py
   ```
   Validates JWT token issuance, authenticated access to endpoints, and error handling.

2. **Verify Live SOC Telemetry Collector:**
   ```bash
   python backend/verify_live_soc_telemetry.py
   ```
   Tests real-time SSH polling and metric collection from target lab nodes.

3. **Verify WebSocket Live Broadcasting:**
   ```bash
   python backend/test_websocket.py
   ```
   Connects to `/ws/telemetry` to verify event streaming without polling.

4. **Run Automated Test Suite:**
   ```bash
   pytest backend/tests/
   ```

---

## 🛡️ Safety Constraints & Lab Isolation Policies

Cyberary-AI is built around strict ethical engineering guidelines:

1. **RFC 1918 Private Address Enforcement:**
   All offensive scans, probes, and simulated exploits reject public IP addresses at the schema validator layer. Accepted ranges:
   - `10.0.0.0` - `10.255.255.255` (10/8 prefix)
   - `172.16.0.0` - `172.31.255.255` (172.16/12 prefix)
   - `192.168.0.0` - `192.168.255.255` (192.168/16 prefix)
   - `127.0.0.1` (Localhost Loopback)

2. **Strict Lab Isolation Mode:**
   When `lab_mode` is enabled in Settings (default), all subagent routines are prevented from executing socket connections outside registered assets.

3. **Immutable Audit Logging:**
   All sensitive operator actions (approvals, rejections, patch executions, target enrolments) are recorded to an append-only cryptographic ledger with timestamp and client IP.

4. **Human-in-the-Loop Gate:**
   No remediation patch is ever applied automatically to a target without explicit operator review and manual approval.

---

## 👥 Contributors & Academic Acknowledgments

- **Platform Architecture & Development:** Cyberary-AI Core Team
- **Autonomous Exploit Engine:** Inspired by *Richard Fang, Rohan Bindu, Akul Gupta, Qiusi Zhan, Daniel Kang* (2024), *"Teams of LLM Agents can Exploit Zero-Day Vulnerabilities"*.
- **Generative Decoy Concept:** Grounded in *shelLM: Generating Shell Decoys with Large Language Models* (2024).
- **Concurrency Research:** Based on the *ACIDRain* transactional concurrency testing methodology.

---

*Cyberary-AI — Empowering Defenders through Autonomous Intelligence.*
