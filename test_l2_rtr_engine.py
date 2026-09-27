import json
from crowdstrike_rtr_engine import CrowdStrikeRTREngine

rtr = CrowdStrikeRTREngine()

# 1. Test Remote Console Session & File Purge
session = rtr.initiate_rtr_session(host_id="WKS-CORP-LON-084", analyst_id="ANALYST-L2-SUBHO")
sess_id = session["session_id"]
print(f"[+] Connected to Remote Terminal: {sess_id}")

# Change dir and delete dropped payload
rtr.execute_terminal_command(sess_id, "cd C:\\Users\\Public\\Temp")
purge_res = rtr.execute_terminal_command(sess_id, "rd /s /q malicious_loader.exe")
print(json.dumps(purge_res, indent=2))

# 2. Test Quarantined File Action
quarantine_res = rtr.manage_quarantined_artifact(
    host_id="WKS-CORP-LON-084",
    file_hash="9f83c12a76f2d59e31b74a98012356cbafe123456789abcdef",
    action="DELETE_FROM_DISK"
)
print(json.dumps(quarantine_res, indent=2))

# 3. Test USB Hardware Insertion & Removable Media Threat Check
usb_telemetry = [
    {
        "event_type": "RemovableDiskVolumeCreated",
        "device_name": "SanDisk Ultra USB 3.0",
        "assigned_drive": "D:",
        "accessed_files": ["Meeting_Notes.pdf", "update_patch.vbs"]
    }
]

usb_analysis = rtr.audit_removable_media_events(usb_telemetry)
print("\n[+] USB Forensic Telemetry Investigation:")
print(json.dumps(usb_analysis, indent=2))