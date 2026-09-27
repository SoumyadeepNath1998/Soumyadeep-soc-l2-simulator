import json
from siem_correlator import SIEMCorrelator

correlator = SIEMCorrelator()

# Mock CrowdStrike Behavioral Events
mock_crowdstrike_events = [
    {
        "parent_process_name": "EXCEL.EXE",
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA...",
        "sha256": "4b68c076bc1234abcd5678ef901234567890abcdef1234567890abcdef123456",
        "mitre_tactic": "TA0002 - Execution"
    }
]

# Mock Chronicle UDM Logs
mock_chronicle_udm = [
    {
        "metadata": {"event_type": "NETWORK_CONNECTION"},
        "principal": {"ip": "10.45.12.89", "hostname": "WKS-CORP-LON-084"},
        "target": {"ip": "185.220.101.5", "hostname": "c2.malicious-gateway-cdn.top"},
        "network": {
            "direction": "OUTBOUND",
            "destination_port": 8443,
            "bytes_sent": 1450200
        }
    }
]

result = correlator.correlate_events(mock_chronicle_udm, mock_crowdstrike_events)
print("=== Chronicle UDM + CrowdStrike Correlated Result ===")
print(json.dumps(result, indent=2))