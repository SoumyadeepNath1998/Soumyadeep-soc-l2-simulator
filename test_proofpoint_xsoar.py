import json
from proofpoint_xsoar_pipeline import ProofpointXSOARPipeline

# Mock Proofpoint TAP alert data
mock_tap_alerts = [
    {
        "threatId": "PPT-THREAT-2026-904",
        "sender": "executive-payroll@spoofed-domain.com",
        "recipient": "employee@carrier-enterprise.com",
        "threatType": "Credential Phishing (URL Redirect)",
        "threatStatus": "active",
        "targetedAttackIndex": 850,
        "header_auth": {"spf": "fail", "dkim": "fail", "dmarc": "fail"},
        "url_click_telemetry": {
            "user_clicked": True,
            "clicked_url_rewritten": True,
            "post_click_action": "BLOCKED_BY_PROOFPOINT_SANDBOX"
        }
    }
]

# Mock Chronicle Raw Ingestion stream (used when XSOAR drops offline)
mock_chronicle_raw_stream = [
    {
        "timestamp": "2026-09-27T17:00:00Z",
        "raw_text": "CEF:0|Proofpoint|TAP_Alert|2026.1|url_defense|Credential Phishing Click|8|threat_id=PPT-THREAT-2026-904 dst=employee@carrier-enterprise.com"
    }
]

# SCENARIO 1: Cortex XSOAR Online (Normal Automation)
print("=" * 60)
print("SCENARIO 1: Normal Ingestion via Cortex XSOAR (Online)")
print("=" * 60)
pipeline = ProofpointXSOARPipeline(xsoar_status="ONLINE")
res_online = pipeline.process_incoming_alerts(mock_tap_alerts, mock_chronicle_raw_stream)
print(json.dumps(res_online, indent=2))

# SCENARIO 2: Cortex XSOAR Down (Chronicle Raw Failover Reconciliation)
print("\n" + "=" * 60)
print("SCENARIO 2: XSOAR Engine Offline -> Chronicle Raw Log Failover")
print("=" * 60)
pipeline.set_xsoar_heartbeat("DOWN")
res_offline = pipeline.process_incoming_alerts(mock_tap_alerts, mock_chronicle_raw_stream)
print(json.dumps(res_offline, indent=2))