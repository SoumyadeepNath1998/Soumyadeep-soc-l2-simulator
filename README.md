# Enterprise Tier-2 SOC Analyst & Security Operations Suite

![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue.svg)
![Architecture](https://img.shields.io/badge/Architecture-Tier--2%20Incident%20Response-success.svg)
![Security Framework](https://img.shields.io/badge/Standard-NIST%20SP%20800--61r2%20%7C%20ISO%2027001-orange.svg)
![Compliance](https://img.shields.io/badge/Data%20Sanitization-NDAA%20Compliant-brightgreen.svg)

An enterprise-grade Level 2 Security Operations Center (SOC) simulation and orchestration suite. This project demonstrates core Tier-2 incident response workflows, multi-source telemetry correlation, live endpoint response (RTR), IPAM asset attribution, alert fine-tuning, and stakeholder governance.

---

## Operational Architecture

[Inbound Threat Vectors / Telemetry Streams]
├── Shared Mailbox (Phishing / Identity Anomaly)
├── SOAR Alert Stream (TAP Ingestion / Outage Failover)
└── Hardware / Removable Media Ingestion
│
▼
[Tier-2 SOC Investigation Orchestrator]
├── Chronicle UDM + EDR Behavioral Correlation
├── BlueCat IPAM Subnet & Blast Radius Attribution
└── CrowdStrike RTR Console & Removable Drive Forensics
│
▼
[Operational Actions & Governance]
┌─────────────────────┼─────────────────────┐
▼                     ▼                     ▼
[Incident RCA Dossier] [Weekly Tuning Engine] [Shift Governance]
(NIST SP 800-61r2)     (FP Noise Reduction)   (SLA / Client Dispatch)


---

## Core Engineering Capabilities

### 1. Shift Governance & Daily Client Dispatch (`sir_shift_governance.py`)
- **Morning Shift Handoff:** Audits L1, L2, and L3 active queues; tracks aging tickets and triggers early warning flags on tickets consuming $>75\%$ of SLA.
- **Aging Ticket Remediation:** Evaluates stale incidents against historical telemetry to execute systematic closure under standard SOC protocols.
- **Afternoon Client Dispatch:** Generates formal end-of-shift operational email summaries detailing P1/P2 resolution metrics, active containment, and next steps.

### 2. Shared Mailbox & Identity Threat Triage (`mailbox_triage.py`)
- **Header Analysis:** Verifies SPF, DKIM, and DMARC alignment, identifying spoofed envelope sender vs. display domain discrepancies.
- **Intent-Based Routing:** Separates general IT requests (auto-forwarding to Service Desk) from security threats.
- **Identity Triage:** Ingests Azure AD impossible travel and MFA fatigue alerts, assigning SLA-aligned ServiceNow SIR priorities.

### 3. SIEM Correlator (`siem_correlator.py`)
- **Multi-Source Lineage:** Merges endpoint behavioral telemetry (process spawning, encoded PowerShell execution) with Chronicle UDM network and authentication logs.
- **Attack Chain Reconstruction:** Maps correlated telemetry directly to MITRE ATT&CK Tactics (Execution, Defense Evasion, Exfiltration).

### 4. Live Response (RTR) Engine & Peripheral Forensics (`crowdstrike_rtr_engine.py`)
- **Interactive RTR Console:** Simulates remote shell commands (`cd`, `get`, `rd /s /q`) for staging containment and purging dropped artifacts.
- **Quarantine Governance:** Manages endpoint artifact deletion and safe restoration workflows.
- **Removable Media Forensics:** Audits `DeviceArrival` and volume mounting telemetry to detect execution staging from external USB drives.

### 5. BlueCat IPAM Asset Attribution (`bluecat_ipam.py`)
- **Subnet Mapping:** Resolves private RFC1918 addresses into distinct network zones (Corporate Workstation, Production DB Cluster, OT/SCADA, VPN Pools).
- **Blast Radius & Criticality:** Assigns asset criticality tiers (Tier-1 Mission Critical vs. Tier-3 Standard) and enforces containment caution policies to avoid unintended enterprise operational disruption.

### 6. Pipeline Ingestion & Outage Failover (`proofpoint_xsoar_pipeline.py`)
- **API Alert Normalization:** Ingests Targeted Attack Protection (TAP) alerts with click-time sandbox verdicts.
- **Failover Resilience:** Automatically shifts to Chronicle raw regex/log queries when SOAR engines report an offline heartbeat, preventing silent ticket drops.

### 7. Friday Alert Fine-Tuning Engine (`friday_tuning_engine.py`)
- **Noise Reduction:** Analyzes 7-day alert volumes to detect detection rules exceeding a 70% False Positive threshold.
- **Detection Engineering Deliverables:** Generates structured engineering proposals (regex refactoring, signer whitelisting) for detection rule optimization.

### 8. Executive Root Cause Analysis Generator (`rca_generator.py`)
- Formats verified incident indicators, containment records, chronological timelines, and Lessons Learned into an executive Markdown dossier aligned with NIST SP 800-61r2 standards.

---

## Directory Structure

```bash
SOC-L2-ANALYST-AI-SIMULATOR/
├── app.py                       # Unified Streamlit operations console
├── mailbox_triage.py            # Mailbox, SPF/DKIM & identity parser
├── siem_correlator.py           # Chronicle UDM + EDR correlation
├── crowdstrike_rtr_engine.py    # Remote console, quarantine & USB engine
├── bluecat_ipam.py              # IPAM subnet resolution & asset tracking
├── proofpoint_xsoar_pipeline.py # SOAR ingestion & failover handler
├── friday_tuning_engine.py      # Weekly FP analysis & detection tuning
├── sir_shift_governance.py      # Shift handoffs, aging audit & dispatch
├── rca_generator.py             # Incident RCA & lessons learned generator
├── requirements.txt             # Project dependencies
└── README.md                    # Project documentation
