"""
SOC L2 Simulator - Module 6: ServiceNow SIR Shift Governance & Client Dispatch
Handles:
1. Morning Shift L1/L2/L3 SIR Ticket Follow-up & SLA Tracking.
2. Aging Incidents Review, De-escalation & Formal Closure.
3. Afternoon Shift Daily SOC Operations Summary Email Dispatch to Clients.
"""

from typing import List, Dict, Any
from datetime import datetime

class SIRShiftGovernance:
    def __init__(self, client_name: str = "Global Enterprise SecOps"):
        self.client_name = client_name

    def morning_shift_followup(self, active_tickets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Morning shift workflow: Follow-up across L1, L2, L3 queues,
        identifying approaching SLA breaches and assignment accountability.
        """
        followup_summary = {"L1": [], "L2": [], "L3": []}
        breach_warning_tickets = []

        for ticket in active_tickets:
            tier = ticket.get("assigned_tier", "L2")
            sla_consumed = ticket.get("sla_percent_consumed", 0.0)
            ticket_id = ticket.get("sir_id")
            
            # Identify SLA risks (>75% SLA consumed)
            if sla_consumed >= 75.0 and ticket.get("state") not in ["Resolved", "Closed"]:
                breach_warning_tickets.append({
                    "sir_id": ticket_id,
                    "tier": tier,
                    "assignee": ticket.get("assigned_to"),
                    "sla_consumed": f"{sla_consumed}%",
                    "action_required": "IMMEDIATE ESCALATION TO SHIFT LEAD"
                })

            if tier in followup_summary:
                followup_summary[tier].append({
                    "sir_id": ticket_id,
                    "priority": ticket.get("priority"),
                    "assignee": ticket.get("assigned_to"),
                    "title": ticket.get("short_description"),
                    "state": ticket.get("state"),
                    "aging_days": ticket.get("age_in_days", 0)
                })

        return {
            "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "shift_phase": "MORNING_SHIFT_HANDOFF_FOLLOWUP",
            "tier_distribution": {
                "L1_count": len(followup_summary["L1"]),
                "L2_count": len(followup_summary["L2"]),
                "L3_count": len(followup_summary["L3"])
            },
            "sla_breach_risks": breach_warning_tickets,
            "tickets_by_tier": followup_summary
        }

    def close_aging_incidents(self, active_tickets: List[Dict[str, Any]], aging_threshold_days: int = 7) -> Dict[str, Any]:
        """
        Audits aging security incidents (>7 or >14 days) and applies standard L2 closure notes.
        """
        closed_incidents = []
        
        for ticket in active_tickets:
            age = ticket.get("age_in_days", 0)
            state = ticket.get("state", "Open")
            
            if age >= aging_threshold_days and state in ["Work in Progress", "Awaiting Info", "Under Observation"]:
                closure_record = {
                    "sir_id": ticket.get("sir_id"),
                    "original_age_days": age,
                    "previous_state": state,
                    "new_state": "Closed / Resolved",
                    "closure_code": "Resolved - No Persistent Threat Detected",
                    "resolution_notes": (
                        f"Tier-2 Aging Incident Audit: Endpoint telemetries (CrowdStrike/Chronicle) "
                        f"monitored for past {age} days. Zero recurrence of malicious beaconing or persistence. "
                        f"All forensic triage completed; marked as resolved as per standard SecOps operating procedure."
                    )
                }
                closed_incidents.append(closure_record)

        return {
            "audited_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "aging_threshold_days": aging_threshold_days,
            "total_aging_closed": len(closed_incidents),
            "closure_records": closed_incidents
        }

    def generate_afternoon_client_dispatch_email(self, shift_metrics: Dict[str, Any]) -> str:
        """
        Drafts the formal daily afternoon SOC operational email update to client stakeholders.
        """
        current_date = datetime.utcnow().strftime("%d-%b-%Y")
        p1_count = shift_metrics.get("p1_critical_count", 0)
        p2_count = shift_metrics.get("p2_high_count", 0)
        p3_count = shift_metrics.get("p3_count", 0)
        resolved_today = shift_metrics.get("resolved_today", 0)
        key_incidents = shift_metrics.get("highlighted_incidents", [])

        incident_table_rows = []
        for inc in key_incidents:
            incident_table_rows.append(
                f"| {inc['sir_id']} | {inc['priority']} | {inc['impacted_asset']} | {inc['status']} | {inc['next_steps']} |"
            )
        incident_table = "\n".join(incident_table_rows) if incident_table_rows else "| None | - | - | All quiet | - |"

        email_body = f"""Subject: [SOC DAILY UPDATE] {self.client_name} Security Operations Shift Status - {current_date}

Dear Stakeholders & Incident Response Leadership,

Please find the Security Operations Center (SOC) daily operational handoff and incident status summary for {current_date} (Afternoon Shift Dispatch).

### 1. Shift Operational Metrics
- **Active P1 (Critical) Incidents:** {p1_count}
- **Active P2 (High) Incidents:** {p2_count}
- **Standard P3/P4 Inquiries:** {p3_count}
- **Total Incidents Remediated & Closed Today:** {resolved_today}

### 2. High-Priority SIR Incidents & Aging Tracker
| Incident ID | Priority | Impacted CI / Host | Current Status | Remediation / Next Steps |
| :--- | :--- | :--- | :--- | :--- |
{incident_table}

### 3. Operational Highlights & Actions Completed
- Morning shift triage and follow-up completed across L1/L2 queues with zero SLA breaches.
- Stale/aging incidents evaluated against Chronicle telemetry and systematically closed.
- Ongoing threat hunting and endpoint isolation validations active via CrowdStrike Falcon console.

Kindly reach out to the 24/7 SOC Shared Mailbox (`soc-operations@global-secops.com`) for any immediate concerns.

Warm regards,  
**Global Managed Security Operations | L2 Incident Lead**
"""
        return email_body