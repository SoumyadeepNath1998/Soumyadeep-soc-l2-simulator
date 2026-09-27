"""
SOC L2 Simulator - Module 2: Enterprise Root Cause Analysis (RCA) & Lessons Learned Engine
Converts verified L2 incident triage and investigation data into an executive RCA markdown report.
"""

from datetime import datetime
from typing import Dict, Any, List

class RCAGenerator:
    def __init__(self, organization: str = "Enterprise Global Security Operations"):
        self.organization = organization

    def generate_rca_report(self, incident_data: Dict[str, Any]) -> str:
        """
        Creates an executive markdown RCA dossier ready for CISO/Stakeholder presentation.
        """
        report_timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        inc_id = incident_data.get("incident_id", "INC-UNDEFINED")
        severity = incident_data.get("severity", "P2 - High")
        target_asset = incident_data.get("impacted_asset", "Unknown Host")
        attributed_actor = incident_data.get("attributed_threat_group", "Uncorrelated External Threat")
        vector = incident_data.get("initial_access_vector", "Spearphishing Link")
        
        timeline_items = incident_data.get("timeline", [])
        timeline_md = "\n".join([f"- **[{item['time']}]**: {item['event']}" for item in timeline_items])
        
        iocs = incident_data.get("iocs", {})
        ioc_md = f"""- **Malicious IPs**: {', '.join(iocs.get('ips', ['None']))}
- **Domains**: {', '.join(iocs.get('domains', ['None']))}
- **SHA-256 Hashes**: {', '.join(iocs.get('hashes', ['None']))}"""

        mitre_mapping = incident_data.get("mitre_techniques", [])
        mitre_md = "\n".join([f"- `{tech['id']}` - {tech['name']}: {tech['context']}" for tech in mitre_mapping])

        lessons_learned = incident_data.get("lessons_learned", [])
        lessons_md = "\n".join([f"{idx+1}. {lesson}" for idx, lesson in enumerate(lessons_learned)])

        rca_template = f"""# ROOT CAUSE ANALYSIS (RCA) & LESSONS LEARNED REPORT
**Document Reference:** RCA-{inc_id}  
**Classification:** TLP:AMBER (Internal Security Stakeholders Only)  
**Reporting Entity:** {self.organization} (Tier-2 SOC)  
**Date Generated:** {report_timestamp}  

---

### 1. Executive Summary
During the operational shift, Tier-2 SOC investigated security incident **{inc_id}** assessed at **{severity}**. The incident manifested via **{vector}**, targeting enterprise asset **{target_asset}**. Attribution indicators lean towards **{attributed_actor}**. Active containment actions were executed under standard SLA guidelines to prevent lateral exposure and privilege escalation.

### 2. Incident Scope & Impacted Assets
- **Incident ID:** {inc_id}
- **Severity / SLA Status:** {severity} (Met SLA)
- **Primary Compromised Asset:** `{target_asset}`
- **Attribution / Campaign:** `{attributed_actor}`
- **Initial Attack Vector:** {vector}

### 3. Chronological Incident Timeline
{timeline_md}

### 4. MITRE ATT&CK Mapping & Threat Tactics
{mitre_md}

### 5. Indicators of Compromise (IOCs) Extracted
{ioc_md}

### 6. Root Cause
The initial intrusion occurred due to execution of an unverified malicious script delivered via a targeted external email which bypassed perimeter gateway controls. Host-level script protections were bypassed via living-off-the-land techniques (PowerShell obfuscation).

### 7. Containment & Remediation Actions Taken
- Host `{target_asset}` isolated from internal VLAN via CrowdStrike network containment.
- Compromised user Active Directory session terminated; password force-reset initiated.
- Network-level blocks pushed to Perimeter Firewalls and Proxies for all extracted IOCs.

### 8. Lessons Learned & Strategic Recommendations
{lessons_md}

---
*Report certified by: Tier-2 Incident Response Analyst (Operations Lead)*
"""
        return rca_template