"""
SOC L2 Simulator - CrowdStrike Real Time Response (RTR) & Peripheral Investigation Engine
Simulates remote containment, live response terminal operations (cd, rd, rm),
file quarantine governance, and USB/external device threat tracking.
"""

from typing import Dict, Any, List
from datetime import datetime

class CrowdStrikeRTREngine:
    def __init__(self):
        self.active_sessions = {}
        self.quarantine_vault = {}

    def initiate_rtr_session(self, host_id: str, analyst_id: str) -> Dict[str, Any]:
        """
        Spawns a remote interactive Live Response (RTR) console session on targeted endpoint.
        """
        session_id = f"RTR-SESS-{host_id[-6:]}-{int(datetime.utcnow().timestamp())}"
        self.active_sessions[session_id] = {
            "host_id": host_id,
            "analyst": analyst_id,
            "connected_at": datetime.utcnow().isoformat() + "Z",
            "working_directory": "C:\\Windows\\System32"
        }
        return {"session_id": session_id, "status": "CONNECTED", "base_dir": "C:\\Windows\\System32"}

    def execute_terminal_command(self, session_id: str, command: str) -> Dict[str, Any]:
        """
        Executes Live Response commands like directory traversal, file removal, or deletion.
        """
        if session_id not in self.active_sessions:
            return {"error": "Invalid or expired RTR session ID"}

        cmd = command.strip()
        current_dir = self.active_sessions[session_id]["working_directory"]
        output = ""

        # Traversal: cd
        if cmd.startswith("cd "):
            target_path = cmd.split(" ", 1)[1]
            self.active_sessions[session_id]["working_directory"] = target_path
            output = f"Working directory altered to: {target_path}"

        # Directory / File Deletion: rd / rm / del
        elif cmd.startswith("rd") or cmd.startswith("rm") or cmd.startswith("del"):
            target_file = cmd.split(" ")[-1]
            output = f"[+] Host Action Success: Remotely purged malicious artifact '{target_file}' from host disk."

        # Host Artifact Detonation/Extraction: get
        elif cmd.startswith("get "):
            target_file = cmd.split(" ", 1)[1]
            output = f"[+] File extracted safely to Tier-2 SOC Sandbox analysis staging: {target_file}"

        else:
            output = f"Executed '{cmd}' successfully on remote agent."

        return {
            "session_id": session_id,
            "executed_command": cmd,
            "result_status": "SUCCESS",
            "console_output": output
        }

    def manage_quarantined_artifact(self, host_id: str, file_hash: str, action: str) -> Dict[str, Any]:
        """
        Enforces L2 governance: permanently delete or restore falsely quarantined binaries.
        """
        actions_allowed = ["DELETE_FROM_DISK", "RESTORE_TO_ENDPOINT"]
        if action not in actions_allowed:
            return {"status": "FAILED", "reason": f"Action must be one of {actions_allowed}"}

        return {
            "host_id": host_id,
            "file_hash": file_hash,
            "action_executed": action,
            "audit_trail": f"Artifact {file_hash} marked as {action} by L2 Analyst at {datetime.utcnow().isoformat()}Z"
        }

    def audit_removable_media_events(self, device_events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Investigates USB insertions and checks whether malicious payloads were staged from external volumes.
        """
        usb_incident_detected = False
        findings = []

        for event in device_events:
            event_type = event.get("event_type")
            device_name = event.get("device_name", "Unknown USB")
            drive_letter = event.get("assigned_drive", "E:")
            files_accessed = event.get("accessed_files", [])

            if event_type == "RemovableDiskVolumeCreated":
                # Check if files from external drive initiated execution
                for f in files_accessed:
                    if f.endswith((".exe", ".vbs", ".bat", ".scr", ".dll")):
                        usb_incident_detected = True
                        findings.append({
                            "device": device_name,
                            "drive": drive_letter,
                            "suspicious_binary": f,
                            "verdict": "MALICIOUS_EXECUTION_FROM_USB",
                            "severity": "CRITICAL"
                        })

        return {
            "usb_investigation_complete": True,
            "compromise_identified": usb_incident_detected,
            "telemetry_findings": findings
        }