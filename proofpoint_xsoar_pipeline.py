"""
SOC L2 Simulator - Module 3: Proofpoint TAP Ingestion, XSOAR Pipeline & Failover Correlator
Handles Proofpoint Targeted Attack Protection (TAP) alerts ingested via Cortex XSOAR.
Includes automatic failover triage via Chronicle raw ingestion when XSOAR is down.
"""

from typing import Dict, Any, List
from datetime import datetime

class ProofpointXSOARPipeline:
    def __init__(self, xsoar_status: str = "ONLINE"):
        self.xsoar_status = xsoar_status.upper()

    def set_xsoar_heartbeat(self, status: str):
        """Toggle Cortex XSOAR engine status: ONLINE or DOWN."""
        self.xsoar_status = status.upper()

    def parse_proofpoint_tap_alert(self, alert_payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parses Proofpoint TAP telemetry: threat details, email authentication,
        and click-time URL sandboxing indicators.
        """
        threat_type = alert_payload.get("threatType", "Unknown")
        threat_status = alert_payload.get("threatStatus", "Active")
        auth_status = alert_payload.get("header_auth", {})
        click_details = alert_payload.get("url_click_telemetry", {})
        
        spf = auth_status.get("spf", "neutral").lower() == "pass"
        dkim = auth_status.get("dkim", "neutral").lower() == "pass"
        dmarc = auth_status.get("dmarc", "neutral").lower() == "pass"
        
        url_redirected = click_details.get("clicked_url_rewritten", False)
        click_verdict = click_details.get("post_click_action", "BLOCKED")
        
        is_targeted = alert_payload.get("targetedAttackIndex", 0) > 700

        risk_score = 0
        if not (spf and dkim and dmarc):
            risk_score += 30
        if is_targeted:
            risk_score += 40
        if click_details.get("user_clicked", False):
            risk_score += 30

        return {
            "threat_id": alert_payload.get("threatId", "TAP-GENERIC"),
            "sender": alert_payload.get("sender", ""),
            "recipient": alert_payload.get("recipient", ""),
            "threat_type": threat_type,
            "threat_status": threat_status,
            "auth_summary": {"spf": spf, "dkim": dkim, "dmarc": dmarc},
            "is_vip_targeted": is_targeted,
            "click_time_analysis": {
                "user_clicked": click_details.get("user_clicked", False),
                "url_rewritten": url_redirected,
                "sandbox_verdict": click_verdict
            },
            "calculated_risk_score": risk_score
        }

    def process_incoming_alerts(self, tap_alerts: List[Dict[str, Any]], chronicle_raw_ingestion: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Triages alerts via XSOAR automated ingestion. If XSOAR is DOWN,
        fails over to Chronicle raw event logs for manual L2 reconciliation.
        """
        triage_results = []

        if self.xsoar_status == "ONLINE":
            pipeline_mode = "XSOAR_AUTOMATED_PLAYBOOK_PROCESSING"
            for alert in tap_alerts:
                parsed = self.parse_proofpoint_tap_alert(alert)
                triage_results.append({
                    "ingestion_channel": "Cortex XSOAR (Proofpoint TAP API)",
                    "ticket_created": True,
                    "incident_id": f"XSOAR-{parsed['threat_id']}",
                    "severity": "P1 - Critical" if parsed["calculated_risk_score"] >= 70 else "P2 - High",
                    "details": parsed
                })
        else:
            # FAILOVER: XSOAR Down -> Reconcile directly via Chronicle Raw Logs
            pipeline_mode = "CHRONICLE_RAW_INGESTION_FAILOVER (MANUAL L2 TRIAGE)"
            for raw_log in chronicle_raw_ingestion:
                log_text = raw_log.get("raw_text", "")
                if "proofpoint" in log_text.lower() or "tap_alert" in log_text.lower():
                    triage_results.append({
                        "ingestion_channel": "Chronicle Raw Ingestion Search (UDM Failover)",
                        "ticket_created": False,
                        "requires_manual_ticket": True,
                        "raw_log_match": log_text,
                        "l2_action": "Manually raise ServiceNow SIR incident due to XSOAR engine outage."
                    })

        return {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "pipeline_state": self.xsoar_status,
            "execution_mode": pipeline_mode,
            "processed_alerts": triage_results
        }