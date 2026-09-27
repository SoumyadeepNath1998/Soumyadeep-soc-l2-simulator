"""
SOC L2 Simulator - Module 2: Chronicle UDM & CrowdStrike NG SIEM Correlation Engine
Reconstructs full attack chains by correlating Chronicle UDM events with
CrowdStrike Falcon behavioral telemetry and process lineage.
"""

from typing import Dict, Any, List
from datetime import datetime

class SIEMCorrelator:
    def __init__(self):
        # Known High-Risk Process Names for Living-off-the-Land (LotL)
        self.suspicious_binaries = ["powershell.exe", "cmd.exe", "wmic.exe", "certutil.exe", "mshta.exe", "rundll32.exe"]

    def correlate_events(self, chronicle_events: List[Dict[str, Any]], crowdstrike_detections: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Correlates Chronicle UDM network/auth events with CrowdStrike process trees.
        """
        correlated_chain = []
        identified_iocs = {"ips": set(), "domains": set(), "hashes": set(), "commands": []}
        mitre_tactics = set()
        escalation_flag = False

        # 1. Parse CrowdStrike Endpoint Telemetry
        for det in crowdstrike_detections:
            parent_proc = det.get("parent_process_name", "").lower()
            child_proc = det.get("process_name", "").lower()
            cmd_line = det.get("command_line", "")
            sha256 = det.get("sha256", "")
            tactic = det.get("mitre_tactic", "")
            
            if tactic:
                mitre_tactics.add(tactic)
            if sha256:
                identified_iocs["hashes"].add(sha256)
            if cmd_line:
                identified_iocs["commands"].append(cmd_line)

            # Detect Spawning Anomalies (e.g., Office/Browser spawning script engines)
            office_apps = ["excel.exe", "winword.exe", "outlook.exe"]
            if any(app in parent_proc for app in office_apps) and any(bin in child_proc for bin in self.suspicious_binaries):
                escalation_flag = True
                correlated_chain.append({
                    "stage": "Execution / Defense Evasion",
                    "source": "CrowdStrike NG SIEM",
                    "finding": f"Suspicious child process '{child_proc}' spawned by '{parent_proc}'.",
                    "command": cmd_line,
                    "severity": "CRITICAL"
                })

        # 2. Correlate with Chronicle UDM Telemetry (Network + Auth)
        for u_event in chronicle_events:
            metadata = u_event.get("metadata", {})
            target = u_event.get("target", {})
            principal = u_event.get("principal", {})
            network = u_event.get("network", {})
            
            event_type = metadata.get("event_type", "")
            dst_ip = target.get("ip", "")
            dst_domain = target.get("hostname", "")

            if dst_ip:
                identified_iocs["ips"].add(dst_ip)
            if dst_domain:
                identified_iocs["domains"].add(dst_domain)

            # Match Network C2 or Exfiltration activity post-execution
            if event_type == "NETWORK_CONNECTION" and network.get("direction") == "OUTBOUND":
                port = network.get("destination_port", 0)
                if port in [4444, 1337, 8080, 8443] or network.get("bytes_sent", 0) > 1000000:
                    escalation_flag = True
                    correlated_chain.append({
                        "stage": "Command & Control / Exfiltration",
                        "source": "Chronicle UDM",
                        "finding": f"High volume outbound traffic or non-standard port: {dst_ip}:{port}",
                        "domain": dst_domain,
                        "severity": "HIGH"
                    })

        # Calculate L2 Confidence & Verdict
        verdict = "CONFIRMED_TRUE_POSITIVE" if escalation_flag else "BENIGN_OR_INCONCLUSIVE"
        l2_priority = "P1 - Critical Escalation" if len(correlated_chain) >= 2 else "P2 - High"

        return {
            "analysis_timestamp": datetime.utcnow().isoformat() + "Z",
            "verdict": verdict,
            "recommended_priority": l2_priority,
            "mitre_tactics_covered": list(mitre_tactics),
            "correlated_timeline": correlated_chain,
            "extracted_iocs": {
                "ips": list(identified_iocs["ips"]),
                "domains": list(identified_iocs["domains"]),
                "hashes": list(identified_iocs["hashes"]),
                "commands": identified_iocs["commands"]
            },
            "next_action": "TRIGGER_HOST_ISOLATION_AND_RCA" if verdict == "CONFIRMED_TRUE_POSITIVE" else "MONITOR_AND_CLOSE"
        }