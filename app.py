"""
Enterprise Tier-2 SOC Analyst Simulator & Operations Dashboard
Neutral Enterprise Architecture (NDAA / Privacy Compliant)
"""

import streamlit as st
import json
from datetime import datetime

# Import Custom L2 Modules
from mailbox_triage import SharedMailboxTriage
from crowdstrike_rtr_engine import CrowdStrikeRTREngine
from siem_correlator import SIEMCorrelator
from proofpoint_xsoar_pipeline import ProofpointXSOARPipeline
from bluecat_ipam import BlueCatIPAM
from friday_tuning_engine import FridayTuningEngine
from sir_shift_governance import SIRShiftGovernance
from rca_generator import RCAGenerator

# Streamlit Page Setup
st.set_page_config(
    page_title="Enterprise Tier-2 SOC Operations Suite",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Styling
st.markdown("""
    <style>
    .main-header { font-size: 26px; font-weight: bold; color: #1E3A8A; }
    .sub-header { font-size: 15px; color: #64748B; margin-bottom: 20px; }
    .status-card { padding: 15px; border-radius: 8px; background-color: #F8FAFC; border: 1px solid #E2E8F0; }
    </style>
""", unsafe_allow_html=True)

# App Header
st.markdown('<div class="main-header">🛡️ Enterprise Tier-2 SOC Autonomous Operations Suite</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Unified Incident Response, Telemetry Correlation, Governance & Detection Engineering Platform</div>', unsafe_allow_html=True)

# Sidebar Navigation
st.sidebar.title("Operational Workflows")
active_tab = st.sidebar.radio(
    "Select Incident / Task Phase:",
    [
        "1. Shift Governance & Daily Dispatch",
        "2. Shared Mailbox Triage (Identity & Email)",
        "3. SIEM Correlator (Chronicle + EDR)",
        "4. Live Response (RTR) & Host Forensics",
        "5. IPAM & Subnet Attribution",
        "6. Ingestion Pipeline & Outage Failover",
        "7. Friday Detection Fine-Tuning",
        "8. Root Cause Analysis (RCA) Generator"
    ]
)

# ==============================================================================
# TAB 1: SHIFT GOVERNANCE & DISPATCH
# ==============================================================================
if active_tab == "1. Shift Governance & Daily Dispatch":
    st.subheader("Shift Handoff, SLA Follow-up & Stakeholder Dispatch")
    gov = SIRShiftGovernance(client_name="Global Enterprise SecOps")

    sample_sir_tickets = [
        {"sir_id": "SIR0092100", "assigned_tier": "L1", "assigned_to": "Analyst_L1", "priority": "P3 - Moderate", "short_description": "User reported suspicious sender in Shared Mailbox", "state": "Work in Progress", "sla_percent_consumed": 40.0, "age_in_days": 1},
        {"sir_id": "SIR0089400", "assigned_tier": "L2", "assigned_to": "Analyst_L2", "priority": "P2 - High", "short_description": "Cobalt Strike beaconing detected on Workstation", "state": "Under Observation", "sla_percent_consumed": 85.0, "age_in_days": 8},
        {"sir_id": "SIR0087010", "assigned_tier": "L3", "assigned_to": "Senior_IR_Lead", "priority": "P1 - Critical", "short_description": "AD Kerberoasting & Lateral Movement Attempt", "state": "Containment Active", "sla_percent_consumed": 55.0, "age_in_days": 15}
    ]

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("#### Morning Shift Handoff & Aging Audit")
        if st.button("Run Morning Shift Audit"):
            followup = gov.morning_shift_followup(sample_sir_tickets)
            aging = gov.close_aging_incidents(sample_sir_tickets, aging_threshold_days=7)
            st.json({"Tier Distribution": followup["tier_distribution"], "SLA Breach Warnings": followup["sla_breach_risks"]})
            st.success(f"Audit completed: {aging['total_aging_closed']} aging tickets evaluated and closed.")

    with col2:
        st.markdown("#### Afternoon Shift Client Summary Email")
        if st.button("Generate Daily Stakeholder Dispatch"):
            shift_metrics = {
                "p1_critical_count": 1,
                "p2_high_count": 1,
                "p3_count": 4,
                "resolved_today": 3,
                "highlighted_incidents": [
                    {"sir_id": "SIR0089400", "priority": "P2 - High", "impacted_asset": "WKS-CORP-LON-084", "status": "Remediated", "next_steps": "Awaiting final telemetry verification."},
                    {"sir_id": "SIR0087010", "priority": "P1 - Critical", "impacted_asset": "DC-PROD-SG-01", "status": "Contained", "next_steps": "Credential rotation complete; zero lateral spread."}
                ]
            }
            dispatch_text = gov.generate_afternoon_client_dispatch_email(shift_metrics)
            st.text_area("Client Communication Output", dispatch_text, height=280)

# ==============================================================================
# TAB 2: SHARED MAILBOX & IDENTITY TRIAGE
# ==============================================================================
elif active_tab == "2. Shared Mailbox Triage (Identity & Email)":
    st.subheader("Shared Mailbox Ingestion & Threat Classification")
    triage = SharedMailboxTriage()

    t_type = st.selectbox("Select Scenario:", ["Identity / Account Lockout Alert", "Phishing / Macro Attachment Inbound", "Non-Security Helpdesk Request"])
    
    if t_type == "Identity / Account Lockout Alert":
        sample_payload = {
            "subject": "Azure AD: Account Lockout - Impossible Travel Detected",
            "body": "User login triggered within 10 minutes across distinct geographic points.",
            "affected_user": "corp.user@enterprise.com",
            "headers": {"Authentication-Results": "spf=pass dkim=pass dmarc=pass"}
        }
    elif t_type == "Phishing / Macro Attachment Inbound":
        sample_payload = {
            "subject": "Urgent: Updated Invoice Ledger Attached",
            "body": "Please review invoice immediately: http://c2-malicious-domain.top/auth",
            "headers": {"Authentication-Results": "spf=fail dkim=fail dmarc=fail", "From": "vendor@partner.com", "Return-Path": "spoof@attacker.ru"},
            "attachments": ["Invoice_Sep2026.xlsm"]
        }
    else:
        sample_payload = {
            "subject": "VPN connection failing from home",
            "body": "Can someone help reset my VPN credentials? Teams is also offline.",
            "headers": {}
        }

    st.write("**Simulated Raw Input Payload:**")
    st.json(sample_payload)

    if st.button("Triage Mailbox Item"):
        res = triage.triage_inbox_item(sample_payload)
        st.write("#### Triage Verdict & Routing:")
        st.json(res)

# ==============================================================================
# TAB 3: SIEM CORRELATOR
# ==============================================================================
elif active_tab == "3. SIEM Correlator (Chronicle + EDR)":
    st.subheader("Multi-Source Telemetry Correlator (Chronicle UDM + EDR Behavioral)")
    correlator = SIEMCorrelator()

    mock_edr = [{
        "parent_process_name": "EXCEL.EXE",
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATw...",
        "sha256": "4b68c076bc1234abcd5678ef901234567890abcdef1234567890abcdef123456",
        "mitre_tactic": "TA0002 - Execution"
    }]
    mock_udm = [{
        "metadata": {"event_type": "NETWORK_CONNECTION"},
        "principal": {"ip": "10.45.12.89", "hostname": "WKS-CORP-LON-084"},
        "target": {"ip": "185.220.101.5", "hostname": "c2.malicious-gateway.top"},
        "network": {"direction": "OUTBOUND", "destination_port": 8443, "bytes_sent": 1450200}
    }]

    if st.button("Correlate Ingested Events"):
        correlation_result = correlator.correlate_events(mock_udm, mock_edr)
        st.json(correlation_result)

# ==============================================================================
# TAB 4: RTR & FORENSICS
# ==============================================================================
elif active_tab == "4. Live Response (RTR) & Host Forensics":
    st.subheader("Real Time Response (RTR) Terminal & Removable Media Forensics")
    rtr = CrowdStrikeRTREngine()

    sess = rtr.initiate_rtr_session("WKS-CORP-LON-084", "ANALYST-L2")
    st.success(f"Active Live Response Session: `{sess['session_id']}` on Host `WKS-CORP-LON-084`")

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("#### Interactive RTR Console")
        cmd_input = st.text_input("Enter RTR Command:", value="rd /s /q malicious_loader.exe")
        if st.button("Execute Terminal Command"):
            rtr_res = rtr.execute_terminal_command(sess['session_id'], cmd_input)
            st.code(rtr_res["console_output"], language="bash")

    with col2:
        st.markdown("#### Hardware & Removable Media Telemetry Audit")
        usb_events = [{
            "event_type": "RemovableDiskVolumeCreated",
            "device_name": "SanDisk Ultra 3.0",
            "assigned_drive": "D:",
            "accessed_files": ["quarterly_review.pdf", "invoice_patch.vbs"]
        }]
        if st.button("Audit USB Detections"):
            usb_res = rtr.audit_removable_media_events(usb_events)
            st.json(usb_res)

# ==============================================================================
# TAB 5: IPAM & ASSET ATTRIBUTION
# ==============================================================================
elif active_tab == "5. IPAM & Subnet Attribution":
    st.subheader("IPAM Subnet Zoning & Asset Attribution Engine")
    ipam = BlueCatIPAM()

    ip_target = st.text_input("Enter IP Address to Attribute:", value="10.100.4.25")
    if st.button("Lookup IPAM Attribution"):
        attribution = ipam.lookup_ip_attribution(ip_target)
        st.json(attribution)

# ==============================================================================
# TAB 6: INGESTION PIPELINE & FAILOVER
# ==============================================================================
elif active_tab == "6. Ingestion Pipeline & Outage Failover":
    st.subheader("Email Security TAP Ingestion & SOAR Outage Failover")
    pipeline = ProofpointXSOARPipeline()

    engine_status = st.radio("Cortex SOAR Heartbeat State:", ["ONLINE", "DOWN"])
    pipeline.set_xsoar_heartbeat(engine_status)

    mock_tap = [{
        "threatId": "PPT-THREAT-2026-904",
        "sender": "payroll@external-spoof.com",
        "recipient": "corp.user@enterprise.com",
        "threatType": "Credential Phishing",
        "targetedAttackIndex": 820,
        "header_auth": {"spf": "fail", "dkim": "fail", "dmarc": "fail"},
        "url_click_telemetry": {"user_clicked": True, "clicked_url_rewritten": True, "post_click_action": "BLOCKED"}
    }]
    mock_raw = [{"timestamp": "2026-09-27T17:00:00Z", "raw_text": "CEF:0|Vendor|TAP_Alert|2026.1|Credential Phishing|8|threat_id=PPT-THREAT-2026-904"}]

    if st.button("Process Ingested Alerts"):
        pipeline_res = pipeline.process_incoming_alerts(mock_tap, mock_raw)
        st.json(pipeline_res)

# ==============================================================================
# TAB 7: FRIDAY DETECTION FINE-TUNING
# ==============================================================================
elif active_tab == "7. Friday Detection Fine-Tuning":
    st.subheader("Weekly Detection Engineering & Alert Noise Reduction")
    tuning = FridayTuningEngine(fp_threshold_percentage=70.0)

    alerts_sample = [
        {"rule_id": "RULE-0941", "rule_name": "PowerShell Unquoted Service Path", "analyst_verdict": "FALSE_POSITIVE", "matched_binary": "C:\\Program Files\\SCCM\\ccmexec.exe"},
        {"rule_id": "RULE-0941", "rule_name": "PowerShell Unquoted Service Path", "analyst_verdict": "FALSE_POSITIVE", "matched_binary": "C:\\Program Files\\SCCM\\ccmexec.exe"},
        {"rule_id": "RULE-0941", "rule_name": "PowerShell Unquoted Service Path", "analyst_verdict": "FALSE_POSITIVE", "matched_binary": "C:\\Program Files\\SCCM\\ccmexec.exe"},
        {"rule_id": "RULE-0941", "rule_name": "PowerShell Unquoted Service Path", "analyst_verdict": "TRUE_POSITIVE", "matched_binary": "C:\\Users\\Public\\bad.exe"},
        {"rule_id": "RULE-002", "rule_name": "Living-off-the-Land Binary", "analyst_verdict": "TRUE_POSITIVE", "matched_binary": "certutil.exe"}
    ]

    if st.button("Generate Weekly Detection Engineering Report"):
        eval_metrics = tuning.evaluate_weekly_alerts(alerts_sample)
        report_md = tuning.generate_friday_report_markdown(eval_metrics)
        st.markdown(report_md)

# ==============================================================================
# TAB 8: ROOT CAUSE ANALYSIS (RCA) GENERATOR
# ==============================================================================
elif active_tab == "8. Root Cause Analysis (RCA) Generator":
    st.subheader("Enterprise Incident Root Cause Analysis (RCA) Dossier")
    rca = RCAGenerator(organization="Global Enterprise Tier-2 SOC")

    sample_rca_data = {
        "incident_id": "SIR0094821",
        "severity": "P1 - Critical Escalation",
        "impacted_asset": "WKS-CORP-LON-084",
        "attributed_threat_group": "FIN7 Emulation / CobaltStrike Stager",
        "initial_access_vector": "Phishing Email with Malicious Macro Workbook",
        "timeline": [
            {"time": "09:12:00 UTC", "event": "User received suspicious email via shared mailbox."},
            {"time": "09:14:22 UTC", "event": "Macro execution triggered hidden PowerShell process."},
            {"time": "09:16:05 UTC", "event": "EDR sensor flagged behavioral anomaly (T1059.001)."},
            {"time": "09:18:00 UTC", "event": "L2 Analyst executed endpoint containment and memory triage."}
        ],
        "mitre_techniques": [
            {"id": "T1566.001", "name": "Spearphishing Attachment", "context": "Inbound XLSM macro file."},
            {"id": "T1059.001", "name": "PowerShell Execution", "context": "Base64 download cradle."}
        ],
        "iocs": {
            "ips": ["185.220.101.5", "194.26.29.112"],
            "domains": ["c2-malicious-domain.top"],
            "hashes": ["9f83c12a76f2d59e31b74a98012356cbafe123456789abcdef0123456789abc"]
        },
        "lessons_learned": [
            "Enforce SEG quarantine on all external XLSM/macro attachments across mail gateways.",
            "Enforce PowerShell Constrained Language Mode on non-admin subnets via GPO.",
            "Tune detection rules to surface obfuscated command-line executions immediately as P2."
        ]
    }

    if st.button("Generate Formal Executive RCA"):
        dossier = rca.generate_rca_report(sample_rca_data)
        st.markdown(dossier)