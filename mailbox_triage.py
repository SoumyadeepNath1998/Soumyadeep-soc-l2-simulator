"""
SOC L2 Simulator - Module 1 (Enhanced): Shared Mailbox Triage & Identity Threat Router
Handles advanced email header analysis (SPF/DKIM/DMARC) and user identity alerts 
(e.g., account lockouts, impossible travel) forwarded to the SOC shared mailbox.
"""

import re
from typing import Dict, Any

class SharedMailboxTriage:
    def __init__(self):
        # Non-security queries for auto-routing
        self.it_helpdesk_keywords = [
            "password reset", "vpn connect", "printer offline", "outlook license",
            "teams access", "laptop slow", "software installation", "docking station"
        ]
        
        # Identity and Identity Threat Keywords
        self.identity_threat_keywords = [
            "account lockout", "impossible travel", "unusual sign-in", 
            "multiple failed logins", "mfa fatigue", "suspicious login"
        ]

    def analyze_email_headers(self, raw_headers: Dict[str, str]) -> Dict[str, Any]:
        """
        Performs L2-level email header analysis for spoofing and domain alignment.
        """
        auth_results = raw_headers.get("Authentication-Results", "").lower()
        return_path = raw_headers.get("Return-Path", "")
        from_address = raw_headers.get("From", "")
        
        dmarc_pass = "dmarc=pass" in auth_results
        spf_pass = "spf=pass" in auth_results
        dkim_pass = "dkim=pass" in auth_results
        
        # Check domain alignment (Return-Path domain vs From domain)
        return_domain = return_path.split('@')[-1].strip('<>') if '@' in return_path else ""
        from_domain = from_address.split('@')[-1].strip('<>') if '@' in from_address else ""
        domain_misaligned = return_domain != from_domain if return_domain and from_domain else False

        spoofing_risk = not (spf_pass and dkim_pass and dmarc_pass) or domain_misaligned

        return {
            "spf_valid": spf_pass,
            "dkim_valid": dkim_pass,
            "dmarc_aligned": dmarc_pass,
            "domain_alignment_failure": domain_misaligned,
            "spoofing_risk": spoofing_risk,
            "analysis_note": "Header anomaly detected (Spoofed Return-Path)" if domain_misaligned else "Headers aligned."
        }

    def process_identity_alert(self, subject: str, body: str, user_id: str = "Unknown") -> Dict[str, Any]:
        """
        Handles Identity/AD related alerts like Account Lockouts or Impossible Travel.
        """
        priority = "P3 - Moderate"
        threat_score = 40
        action = "CREATE_SERVICENOW_SIR_AND_INVESTIGATE"
        
        if "impossible travel" in subject or "impossible travel" in body:
            priority = "P2 - High"
            threat_score = 65
            action = "TRIGGER_AZURE_AD_INVESTIGATION"
        elif "mfa fatigue" in subject or "mfa fatigue" in body:
            priority = "P1 - Critical Escalation"
            threat_score = 85
            action = "REVOKE_SESSION_AND_BLOCK_USER"

        return {
            "classification": "IDENTITY_THREAT_INCIDENT",
            "routing_target": "SOC Tier-2 Identity Queue",
            "action": action,
            "priority": priority,
            "threat_score": threat_score,
            "user_impacted": user_id,
            "recommended_sla": "30 minutes" if priority != "P1 - Critical Escalation" else "15 minutes"
        }

    def triage_inbox_item(self, email_payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main routing function to classify IT Helpdesk, Identity Threats, or Phishing/Malware.
        """
        subject = email_payload.get("subject", "").lower()
        body = email_payload.get("body", "").lower()
        headers = email_payload.get("headers", {})
        attachments = email_payload.get("attachments", [])
        extracted_urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', body)

        # 1. Non-Security IT Routing
        for keyword in self.it_helpdesk_keywords:
            if keyword in subject or keyword in body:
                return {
                    "classification": "NON_SECURITY_REQUEST",
                    "routing_target": "IT Service Desk (Level 1)",
                    "action": "AUTO_FORWARD_AND_RESOLVE"
                }

        # 2. Identity & Account Lockout Routing
        for keyword in self.identity_threat_keywords:
            if keyword in subject or keyword in body:
                user_id = email_payload.get("affected_user", "Extracted_from_body")
                return self.process_identity_alert(subject, body, user_id)

        # 3. Phishing & Payload Security Routing
        auth_analysis = self.analyze_email_headers(headers)
        suspicious_extensions = [".exe", ".scr", ".iso", ".vbs", ".hta", ".zip", ".xlsm", ".lnk"]
        dangerous_attachments = [att for att in attachments if any(att.lower().endswith(ext) for ext in suspicious_extensions)]

        threat_score = 0
        if auth_analysis["spoofing_risk"]: threat_score += 35
        if dangerous_attachments: threat_score += 45
        if extracted_urls: threat_score += 20

        priority = "P3 - Moderate"
        if threat_score >= 70:
            priority = "P1 - Critical Escalation"
        elif threat_score >= 40:
            priority = "P2 - High"

        return {
            "classification": "PHISHING_MALWARE_INCIDENT",
            "routing_target": "SOC Tier-2 Payload Analysis Queue",
            "action": "CREATE_SERVICENOW_SIR",
            "priority": priority,
            "threat_score": threat_score,
            "extracted_urls": extracted_urls,
            "dangerous_attachments": dangerous_attachments,
            "header_integrity": auth_analysis
        }