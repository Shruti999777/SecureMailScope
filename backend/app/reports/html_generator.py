"""
SecureMailScope - Standalone Interactive HTML Report Generator
Generates self-contained, responsive HTML reports with dark theme, stats cards, and findings accordion.
"""

import json
import datetime
from typing import Dict, Any, List


class HTMLReportGenerator:
    """Produces responsive, self-contained HTML assessment reports."""

    @classmethod
    def generate_report_html(
        cls,
        job_data: Dict[str, Any],
        sessions: List[Dict[str, Any]],
        findings: List[Dict[str, Any]],
        certificates: List[Dict[str, Any]]
    ) -> str:
        score = job_data.get("overall_score", 100)
        risk = job_data.get("overall_risk_level", "SECURE")
        grade = job_data.get("security_grade", "A+")
        filename = job_data.get("filename", "capture.pcap")
        job_id = job_data.get("id", "ASM-001")
        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        risk_colors = {
            "SECURE": "#10b981",
            "LOW": "#3b82f6",
            "MEDIUM": "#f59e0b",
            "HIGH": "#f97316",
            "CRITICAL": "#ef4444"
        }
        badge_color = risk_colors.get(risk, "#6b7280")

        # Summarize protocol counts
        proto_counts = {}
        tls_counts = {}
        for s in sessions:
            p = s.get("protocol", "UNKNOWN")
            proto_counts[p] = proto_counts.get(p, 0) + 1
            t = s.get("tls_version", "None")
            tls_counts[t] = tls_counts.get(t, 0) + 1

        findings_html = ""
        if findings:
            for f in findings:
                sev = f.get("severity", "LOW")
                col = risk_colors.get(sev, "#3b82f6")
                findings_html += f"""
                <div class="finding-card" style="border-left: 4px solid {col};">
                    <div class="finding-header">
                        <span class="badge" style="background: {col}22; color: {col}; border: 1px solid {col}55;">{sev}</span>
                        <span class="finding-title">{f.get('rule_id')}: {f.get('title')}</span>
                        <span class="cvss">CVSS: {f.get('cvss_score', 0.0)}</span>
                    </div>
                    <p class="finding-desc"><strong>Observation:</strong> {f.get('description')}</p>
                    <p class="finding-rec"><strong>Remediation:</strong> {f.get('recommendation')}</p>
                    <div class="finding-meta"><span>Stream ID: <code>{f.get('stream_id')}</code></span> <span>Protocol: <code>{f.get('protocol')}</code></span></div>
                </div>
                """
        else:
            findings_html = "<div class='empty-card'>✅ No security vulnerabilities detected. Traffic adheres to cryptographic standards.</div>"

        # Certificate rows
        certs_html = ""
        if certificates:
            for c in certificates:
                c_valid = c.get("chain_valid", True)
                v_col = "#10b981" if c_valid else "#ef4444"
                certs_html += f"""
                <tr>
                    <td><code>{c.get('stream_id')}</code></td>
                    <td><strong>{c.get('subject_cn', 'N/A')}</strong><br><small>{c.get('subject_org', '')}</small></td>
                    <td>{c.get('issuer_cn', 'N/A')}</td>
                    <td><span class="badge" style="background: {v_col}22; color: {v_col}; border: 1px solid {v_col}55;">{c.get('chain_status')}</span></td>
                    <td>{c.get('key_type')} {c.get('key_size')}b</td>
                    <td>{c.get('signature_algorithm')}</td>
                    <td>{c.get('not_after', '')[:10]}</td>
                </tr>
                """
        else:
            certs_html = "<tr><td colspan='7' style='text-align:center;'>No TLS certificates found in capture.</td></tr>"

        # Sessions rows
        sessions_html = ""
        for s in sessions[:30]:
            fs_badge = "✅ Yes" if s.get("forward_secrecy") else "❌ No"
            anom_badge = f"<span class='badge' style='background:#ef444422; color:#ef4444;'>Anomalous</span>" if s.get("is_anomalous") else "<span class='badge' style='background:#10b98122; color:#10b981;'>Normal</span>"
            s_sev = s.get("risk_level", "SECURE")
            s_col = risk_colors.get(s_sev, "#6b7280")

            sessions_html += f"""
            <tr>
                <td><code>{s.get('stream_id')}</code></td>
                <td><span class="badge" style="background:#3b82f622; color:#3b82f6;">{s.get('protocol')}</span></td>
                <td>{s.get('client_ip')}:{s.get('client_port')} &rarr; {s.get('server_ip')}:{s.get('server_port')}</td>
                <td>{s.get('tls_version')}</td>
                <td><small>{s.get('cipher_suite')}</small></td>
                <td>{fs_badge}</td>
                <td><span class="badge" style="background:{s_col}22; color:{s_col}; border:1px solid {s_col}55;">{s_sev}</span></td>
                <td>{anom_badge}</td>
            </tr>
            """

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecureMailScope Audit Report - {filename}</title>
    <style>
        :root {{
            --bg: #0b0f19;
            --card-bg: #111827;
            --card-border: #1f2937;
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --primary: #3b82f6;
            --accent: #06b6d4;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
        body {{ background: var(--bg); color: var(--text-main); line-height: 1.5; padding: 32px 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid var(--card-border); padding-bottom: 20px; margin-bottom: 24px; }}
        .logo-title {{ font-size: 24px; font-weight: 800; letter-spacing: -0.5px; color: #60a5fa; }}
        .logo-subtitle {{ font-size: 13px; color: var(--text-muted); }}
        .grid-4 {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px; }}
        .stat-card {{ background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 10px; padding: 20px; text-align: center; }}
        .stat-val {{ font-size: 32px; font-weight: 800; margin-top: 6px; }}
        .stat-lbl {{ font-size: 12px; font-weight: 600; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.5px; }}
        .section-title {{ font-size: 18px; font-weight: 700; margin: 28px 0 14px 0; color: #e5e7eb; display: flex; align-items: center; gap: 8px; }}
        .finding-card {{ background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 8px; padding: 16px; margin-bottom: 12px; }}
        .finding-header {{ display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }}
        .finding-title {{ font-weight: 700; font-size: 15px; flex-grow: 1; }}
        .cvss {{ font-size: 12px; font-weight: 700; background: #374151; padding: 2px 8px; border-radius: 4px; }}
        .finding-desc {{ font-size: 13.5px; color: #d1d5db; margin-bottom: 6px; }}
        .finding-rec {{ font-size: 13.5px; color: #38bdf8; }}
        .finding-meta {{ margin-top: 10px; font-size: 12px; color: var(--text-muted); display: flex; gap: 16px; }}
        table {{ width: 100%; border-collapse: collapse; background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 8px; overflow: hidden; margin-bottom: 24px; font-size: 13.5px; }}
        th {{ background: #1f2937; text-align: left; padding: 12px; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-muted); }}
        td {{ padding: 12px; border-top: 1px solid var(--card-border); }}
        code {{ background: #1f2937; padding: 2px 6px; border-radius: 4px; font-family: monospace; font-size: 12px; }}
        .badge {{ padding: 3px 8px; border-radius: 6px; font-size: 11.5px; font-weight: 700; display: inline-block; }}
        .empty-card {{ background: var(--card-bg); border: 1px solid var(--card-border); padding: 24px; text-align: center; border-radius: 8px; color: #10b981; font-weight: 600; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <div class="logo-title">SECUREMAILSCOPE</div>
                <div class="logo-subtitle">Cryptographic Security Posture Assessment Report</div>
            </div>
            <div style="text-align: right; font-size: 13px; color: var(--text-muted);">
                <div>Capture: <code>{filename}</code></div>
                <div>Generated: {timestamp}</div>
            </div>
        </header>

        <div class="grid-4">
            <div class="stat-card">
                <div class="stat-lbl">Security Posture Score</div>
                <div class="stat-val" style="color: {badge_color};">{score}/100</div>
            </div>
            <div class="stat-card">
                <div class="stat-lbl">Risk Level</div>
                <div class="stat-val" style="color: {badge_color};">{risk}</div>
            </div>
            <div class="stat-card">
                <div class="stat-lbl">Security Grade</div>
                <div class="stat-val" style="color: #60a5fa;">{grade}</div>
            </div>
            <div class="stat-card">
                <div class="stat-lbl">Total Sessions</div>
                <div class="stat-val">{len(sessions)}</div>
            </div>
        </div>

        <div class="section-title">🚨 Identified Vulnerabilities & Findings ({len(findings)})</div>
        <div>{findings_html}</div>

        <div class="section-title">📜 X.509 Certificate Chain-of-Trust Audit ({len(certificates)})</div>
        <table>
            <thead>
                <tr>
                    <th>Stream</th>
                    <th>Subject CN</th>
                    <th>Issuer CN</th>
                    <th>Chain Status</th>
                    <th>Key Size</th>
                    <th>Signature Hash</th>
                    <th>Valid Until</th>
                </tr>
            </thead>
            <tbody>{certs_html}</tbody>
        </table>

        <div class="section-title">🔍 Email Traffic Reassembly & TLS Sessions ({len(sessions)})</div>
        <table>
            <thead>
                <tr>
                    <th>Stream ID</th>
                    <th>Protocol</th>
                    <th>Client / Server Endpoint</th>
                    <th>TLS Version</th>
                    <th>Cipher Suite</th>
                    <th>Forward Secrecy</th>
                    <th>Risk</th>
                    <th>Behavioral AI</th>
                </tr>
            </thead>
            <tbody>{sessions_html}</tbody>
        </table>
    </div>
</body>
</html>
"""
        return html_content
