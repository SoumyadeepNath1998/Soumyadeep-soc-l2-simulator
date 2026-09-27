from friday_tuning_engine import FridayTuningEngine

engine = FridayTuningEngine(fp_threshold_percentage=70.0)

# Mock historical 7-day alert logs ingested by L2
mock_weekly_alerts = [
    # Rule 1: High noise admin script
    {"rule_id": "CRON-0941", "rule_name": "PowerShell Unquoted Service Path", "analyst_verdict": "FALSE_POSITIVE", "matched_binary": "C:\\Program Files\\SCCM\\ccmexec.exe"},
    {"rule_id": "CRON-0941", "rule_name": "PowerShell Unquoted Service Path", "analyst_verdict": "FALSE_POSITIVE", "matched_binary": "C:\\Program Files\\SCCM\\ccmexec.exe"},
    {"rule_id": "CRON-0941", "rule_name": "PowerShell Unquoted Service Path", "analyst_verdict": "FALSE_POSITIVE", "matched_binary": "C:\\Program Files\\SCCM\\ccmexec.exe"},
    {"rule_id": "CRON-0941", "rule_name": "PowerShell Unquoted Service Path", "analyst_verdict": "TRUE_POSITIVE", "matched_binary": "C:\\Users\\Public\\bad.exe"},
    
    # Rule 2: Legit True Positive rule
    {"rule_id": "CS-BEHAV-002", "rule_name": "Living-off-the-Land Binary Execution", "analyst_verdict": "TRUE_POSITIVE", "matched_binary": "certutil.exe"},
    {"rule_id": "CS-BEHAV-002", "rule_name": "Living-off-the-Land Binary Execution", "analyst_verdict": "TRUE_POSITIVE", "matched_binary": "mshta.exe"}
]

analysis = engine.evaluate_weekly_alerts(mock_weekly_alerts)
report_md = engine.generate_friday_report_markdown(analysis)

print("=== Friday Detection Tuning Report ===")
print(report_md)