import json
from sir_shift_governance import SIRShiftGovernance

gov = SIRShiftGovernance(client_name="Carrier Global Operations")

# Sample Tickets across L1, L2, and L3
mock_sir_tickets = [
    {
        "sir_id": "SIR0092100",
        "assigned_tier": "L1",
        "assigned_to": "Analyst_L1_Deb",
        "priority": "P3 - Moderate",
        "short_description": "User reported suspicious sender in Shared Mailbox",
        "state": "Work in Progress",
        "sla_percent_consumed": 40.0,
        "age_in_days": 1
    },
    {
        "sir_id": "SIR0089400",
        "assigned_tier": "L2",
        "assigned_to": "Analyst_L2_Subho",
        "priority": "P2 - High",
        "short_description": "Cobalt Strike beaconing detected on London Workstation",
        "state": "Under Observation",
        "sla_percent_consumed": 85.0,  # SLA Breach warning
        "age_in_days": 8               # Aging incident
    },
    {
        "sir_id": "SIR0087010",
        "assigned_tier": "L3",
        "assigned_to": "Senior_IR_Lead",
        "priority": "P1 - Critical",
        "short_description": "AD Kerberoasting & Lateral Movement Attempt",
        "state": "Containment Active",
        "sla_percent_consumed": 55.0,
        "age_in_days": 15              # Aging incident
    }
]

# 1. Test Morning Shift Follow-up
print("=" * 60)
print("TEST 1: Morning Shift SIR Follow-up & SLA Tracking")
print("=" * 60)
morning_res = gov.morning_shift_followup(mock_sir_tickets)
print(json.dumps(morning_res, indent=2))

# 2. Test Aging Incident Evaluation & Closure
print("\n" + "=" * 60)
print("TEST 2: Aging Incident Review & Auto-Closure")
print("=" * 60)
aging_res = gov.close_aging_incidents(mock_sir_tickets, aging_threshold_days=7)
print(json.dumps(aging_res, indent=2))

# 3. Test Afternoon Shift Daily Client Dispatch Email
print("\n" + "=" * 60)
print("TEST 3: Afternoon Shift Daily Client Email Dispatch")
print("=" * 60)
shift_metrics = {
    "p1_critical_count": 1,
    "p2_high_count": 1,
    "p3_count": 4,
    "resolved_today": 3,
    "highlighted_incidents": [
        {
            "sir_id": "SIR0089400",
            "priority": "P2 - High",
            "impacted_asset": "WKS-CORP-LON-084",
            "status": "Remediated / Under Observation",
            "next_steps": "Host memory clean; awaiting final verification."
        },
        {
            "sir_id": "SIR0087010",
            "priority": "P1 - Critical",
            "impacted_asset": "DC-APAC-SG-01",
            "status": "Contained",
            "next_steps": "L3 Lead rotating KRBTGT accounts; zero lateral spread."
        }
    ]
}
email_content = gov.generate_afternoon_client_dispatch_email(shift_metrics)
print(email_content)