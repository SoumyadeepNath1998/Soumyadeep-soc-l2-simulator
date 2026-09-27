"""
SOC L2 Simulator - Module 5: Weekly Alert Fine-Tuning & Noise Reduction Engine
Aggregates historical alert telemetry, identifies noisy false positives,
and generates structured tuning recommendations for Detection Engineering.
"""

from typing import List, Dict, Any
from datetime import datetime

class FridayTuningEngine:
    def __init__(self, fp_threshold_percentage: float = 70.0):
        # Rules with False Positive rate >= 70% get flagged for immediate tuning
        self.fp_threshold_percentage = fp_threshold_percentage

    def evaluate_weekly_alerts(self, alert_history: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculates rule volume, FP ratios, and formulates tuning actions.
        """
        metrics = {}
        for alert in alert_history:
            rule_id = alert["rule_id"]
            rule_name = alert["rule_name"]
            verdict = alert["analyst_verdict"]

            if rule_id not in metrics:
                metrics[rule_id] = {
                    "rule_name": rule_name,
                    "total_triggers": 0,
                    "false_positives": 0,
                    "true_positives": 0,
                    "common_benign_binaries": set()
                }

            metrics[rule_id]["total_triggers"] += 1
            if verdict == "FALSE_POSITIVE":
                metrics[rule_id]["false_positives"] += 1
                if "matched_binary" in alert:
                    metrics[rule_id]["common_benign_binaries"].add(alert["matched_binary"])
            else:
                metrics[rule_id]["true_positives"] += 1

        recommendations = []
        for r_id, data in metrics.items():
            fp_rate = (data["false_positives"] / data["total_triggers"]) * 100
            data["fp_rate"] = round(fp_rate, 2)
            data["common_benign_binaries"] = list(data["common_benign_binaries"])

            if fp_rate >= self.fp_threshold_percentage:
                recommendations.append({
                    "rule_id": r_id,
                    "rule_name": data["rule_name"],
                    "fp_rate": f"{data['fp_rate']}%",
                    "triggers": data["total_triggers"],
                    "recommended_action": "SUPPRESSION_OR_REGEX_REFACTOR",
                    "proposal": f"Exclude signed administrative parent paths or benign binaries: {data['common_benign_binaries']}"
                })

        return {
            "evaluation_period": "Past 7 Days",
            "total_rules_analyzed": len(metrics),
            "flagged_for_tuning": len(recommendations),
            "rule_metrics": metrics,
            "tuning_recommendations": recommendations
        }

    def generate_friday_report_markdown(self, analysis_result: Dict[str, Any]) -> str:
        """
        Produces an executive Friday Fine-Tuning & Noise Reduction Report.
        """
        report_date = datetime.utcnow().strftime("%Y-%m-%d")
        recs = analysis_result["tuning_recommendations"]
        
        recs_rows = []
        for rec in recs:
            recs_rows.append(
                f"| `{rec['rule_id']}` | **{rec['rule_name']}** | {rec['triggers']} | {rec['fp_rate']} | {rec['proposal']} |"
            )
        recs_table = "\n".join(recs_rows) if recs_rows else "| None | None | 0 | 0% | All rules operating within standard baseline. |"

        markdown_doc = f"""# WEEKLY SOC DETECTION FINE-TUNING REPORT
**Reporting Cadence:** Friday Weekly Review  
**Date:** {report_date}  
**Author:** Tier-2 SOC Detection & Triage Lead  
**Scope:** SIEM/EDR Alert Noise Reduction & Tuning Proposals  

---

### 1. Executive Summary
During this weekly cycle, **{analysis_result['total_rules_analyzed']} detection rules** were audited across Chronicle and CrowdStrike NG SIEM. A total of **{analysis_result['flagged_for_tuning']} rules** exceeded the acceptable False Positive threshold (>={self.fp_threshold_percentage}%), generating unnecessary operational noise.

### 2. High-Noise Rules Flagged for Action
| Rule ID | Detection Logic | Total Triggers | FP Rate | Recommended Engineering Action |
| :--- | :--- | :--- | :--- | :--- |
{recs_table}

### 3. Strategic Recommendations for Detection Engineering
1. **Whitelist Standardization:** Implement strict signer checks for internal IT administrative maintenance scripts.
2. **Threshold Tuning:** Upgrade single-event volumetric rules to 5-minute rolling threshold aggregations.
3. **Next Steps:** Review proposed suppression lists with L3 SecOps Lead prior to Monday production deployment.

---
*Deliverable approved by: Tier-2 SOC Operations Lead*
"""
        return markdown_doc