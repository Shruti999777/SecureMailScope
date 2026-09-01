"""
SecureMailScope - JSON Audit Export Generator
"""

import json
import datetime
from typing import Dict, Any, List


class JSONReportGenerator:
    """Produces comprehensive machine-readable JSON exports."""

    @classmethod
    def generate_report_dict(
        cls,
        job_data: Dict[str, Any],
        sessions: List[Dict[str, Any]],
        findings: List[Dict[str, Any]],
        certificates: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        return {
            "metadata": {
                "tool": "SecureMailScope",
                "version": "2.0.0",
                "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "assessment_id": job_data.get("id"),
                "filename": job_data.get("filename"),
            },
            "executive_summary": {
                "overall_score": job_data.get("overall_score"),
                "overall_risk_level": job_data.get("overall_risk_level"),
                "security_grade": job_data.get("security_grade"),
                "total_sessions": len(sessions),
                "total_findings": len(findings),
                "created_at": str(job_data.get("created_at")),
                "completed_at": str(job_data.get("completed_at")),
            },
            "traffic_analysis": {
                "sessions": sessions,
            },
            "cryptographic_chain_of_trust": {
                "certificates": certificates,
            },
            "security_findings": findings,
            "ai_insights": job_data.get("summary_data", {}).get("ml_summary", {})
        }
