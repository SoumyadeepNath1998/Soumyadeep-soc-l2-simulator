from mailbox_triage import SharedMailboxTriage
from rca_generator import RCAGenerator

# Test 1: Shared Mailbox Triage
triage = SharedMailboxTriage()

incoming_mail = {
    "subject": "Urgent: Updated Q3 Vendor Invoice Attached",
    "body": "Please review the updated vendor ledger attached immediately: http://malicious-gateway-cdn.top/auth",
    "headers": {"Authentication-Results": "spf=fail dkim=fail dmarc=fail"},
    "attachments": ["Invoice_Sep2026.xlsm"]
}

triage_result = triage.triage_inbox_item(incoming_mail)
print("=== Mailbox Triage Decision ===")
print(triage_result)

# Test 2: Generate Formal RCA
rca = RCAGenerator()

incident_summary = {
    "incident_id": "SIR0094821",
    "severity": "P1 - Critical Escalation",
    "impacted_asset": "WKS-CORP-LON-084",
    "attributed_threat_group": "FIN7 Emulation / CobaltStrike Stager",
    "initial_access_vector": "Phishing Email with Malicious Macro Workbook",
    "timeline": [
        {"time": "09:12:00 UTC", "event": "User received suspicious email via shared vendor mailbox."},
        {"time": "09:14:22 UTC", "event": "Macro execution triggered hidden PowerShell process."},
        {"time": "09:16:05 UTC", "event": "CrowdStrike flagged behavioral anomaly (T1059.001)."},
        {"time": "09:18:00 UTC", "event": "L2 Analyst executed endpoint isolation and host memory triage."}
    ],
    "mitre_techniques": [
        {"id": "T1566.001", "name": "Spearphishing Attachment", "context": "Inbound XLSM macro file."},
        {"id": "T1059.001", "name": "PowerShell Execution", "context": "Base64 encoded download cradle."}
    ],
    "iocs": {
        "ips": ["185.220.101.5", "194.26.29.112"],
        "domains": ["malicious-gateway-cdn.top"],
        "hashes": ["9f83c12a76f2...e31b"]
    },
    "lessons_learned": [
        "Block all XLSM/macro attachments at the Secure Email Gateway level across external domains.",
        "Implement PowerShell Constrained Language Mode on non-administrator subnets via GPO.",
        "Adjust Friday alert fine-tuning to surface obfuscated command-line scripts directly as P2."
    ]
}

report_markdown = rca.generate_rca_report(incident_summary)
print("\n=== Generated RCA Output ===")
print(report_markdown)