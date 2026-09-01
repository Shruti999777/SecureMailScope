"""
SecureMailScope - Executive PDF Report Generator
Generates professional cryptographic posture assessment PDF reports using ReportLab.
"""

import io
import datetime
from typing import Dict, Any, List
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)


class PDFReportGenerator:
    """Creates presentation-ready executive cybersecurity PDF audit reports."""

    @classmethod
    def generate_report_bytes(cls, job_data: Dict[str, Any], sessions: List[Dict[str, Any]], findings: List[Dict[str, Any]], certificates: List[Dict[str, Any]]) -> bytes:
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()
        
        # Custom Typography
        title_style = ParagraphStyle(
            "ReportTitle",
            parent=styles["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=22,
            leading=26,
            textColor=colors.HexColor("#0f172a"),
            spaceAfter=4
        )
        subtitle_style = ParagraphStyle(
            "ReportSubtitle",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=11,
            leading=14,
            textColor=colors.HexColor("#3b82f6"),
            spaceAfter=15
        )
        h2_style = ParagraphStyle(
            "SectionH2",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#1e293b"),
            spaceBefore=12,
            spaceAfter=8
        )
        body_style = ParagraphStyle(
            "ReportBody",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=9.5,
            leading=13,
            textColor=colors.HexColor("#334155")
        )
        table_cell_style = ParagraphStyle(
            "TableCell",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=11,
            textColor=colors.HexColor("#1e293b")
        )
        table_header_style = ParagraphStyle(
            "TableHeader",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=9,
            leading=12,
            textColor=colors.white
        )

        story = []

        # 1. Header Banner
        story.append(Paragraph("SECUREMAILSCOPE", title_style))
        story.append(Paragraph("Cryptographic Security Posture Assessment Report", subtitle_style))
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#3b82f6"), spaceAfter=15))

        # 2. Executive Metadata Box
        meta_data = [
            [
                Paragraph(f"<b>Target Capture:</b> {job_data.get('filename', 'capture.pcap')}", body_style),
                Paragraph(f"<b>Assessment ID:</b> {job_data.get('id', 'ASM-001')}", body_style)
            ],
            [
                Paragraph(f"<b>Generated:</b> {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}", body_style),
                Paragraph(f"<b>Total Sessions Reassembled:</b> {len(sessions)}", body_style)
            ]
        ]
        meta_table = Table(meta_data, colWidths=[270, 270])
        meta_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#e2e8f0")),
            ("PADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 15))

        # 3. Posture Score Card
        score = job_data.get("overall_score", 100)
        risk = job_data.get("overall_risk_level", "SECURE")
        grade = job_data.get("security_grade", "A+")

        risk_bg = colors.HexColor("#22c55e") if risk == "SECURE" else (
            colors.HexColor("#eab308") if risk in ("LOW", "MEDIUM") else colors.HexColor("#ef4444")
        )

        score_card_data = [
            [
                Paragraph("<b>POSTURE SCORE</b>", ParagraphStyle("H", parent=table_cell_style, fontSize=11, fontName="Helvetica-Bold")),
                Paragraph("<b>RISK LEVEL</b>", ParagraphStyle("H", parent=table_cell_style, fontSize=11, fontName="Helvetica-Bold")),
                Paragraph("<b>SECURITY GRADE</b>", ParagraphStyle("H", parent=table_cell_style, fontSize=11, fontName="Helvetica-Bold")),
                Paragraph("<b>FINDINGS TOTAL</b>", ParagraphStyle("H", parent=table_cell_style, fontSize=11, fontName="Helvetica-Bold"))
            ],
            [
                Paragraph(f"<font size=22><b>{score}/100</b></font>", table_cell_style),
                Paragraph(f"<font size=16 color='{risk_bg.hexval()}'><b>{risk}</b></font>", table_cell_style),
                Paragraph(f"<font size=22 color='#2563eb'><b>{grade}</b></font>", table_cell_style),
                Paragraph(f"<font size=22><b>{len(findings)}</b></font>", table_cell_style)
            ]
        ]
        score_table = Table(score_card_data, colWidths=[135, 135, 135, 135])
        score_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
            ("BOX", (0, 0), (-1, -1), 1.5, colors.HexColor("#cbd5e1")),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("PADDING", (0, 0), (-1, -1), 10),
        ]))
        story.append(score_table)
        story.append(Spacer(1, 18))

        # 4. Traffic & Protocol Breakdown
        story.append(Paragraph("1. Protocol & Cryptographic Distribution Summary", h2_style))
        
        proto_counts = {}
        tls_counts = {}
        for s in sessions:
            p = s.get("protocol", "UNKNOWN")
            proto_counts[p] = proto_counts.get(p, 0) + 1
            t = s.get("tls_version", "None")
            tls_counts[t] = tls_counts.get(t, 0) + 1

        dist_data = [
            [Paragraph("Protocol", table_header_style), Paragraph("Sessions", table_header_style), Paragraph("TLS Version", table_header_style), Paragraph("Sessions", table_header_style)]
        ]
        
        p_items = list(proto_counts.items())
        t_items = list(tls_counts.items())
        max_rows = max(len(p_items), len(t_items), 1)

        for i in range(max_rows):
            p_str, p_cnt = p_items[i] if i < len(p_items) else ("", "")
            t_str, t_cnt = t_items[i] if i < len(t_items) else ("", "")
            dist_data.append([
                Paragraph(str(p_str), table_cell_style),
                Paragraph(str(p_cnt), table_cell_style),
                Paragraph(str(t_str), table_cell_style),
                Paragraph(str(t_cnt), table_cell_style)
            ])

        dist_table = Table(dist_data, colWidths=[160, 110, 160, 110])
        dist_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("PADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(dist_table)
        story.append(Spacer(1, 15))

        # 5. X.509 Chain-of-Trust Findings
        story.append(Paragraph("2. X.509 Certificate Chain-of-Trust Audit", h2_style))
        if certificates:
            cert_table_data = [
                [Paragraph("Stream", table_header_style), Paragraph("Subject CN", table_header_style), Paragraph("Issuer CN", table_header_style), Paragraph("Chain Status", table_header_style), Paragraph("Key / Sig", table_header_style)]
            ]
            for c in certificates[:6]:
                status_color = "#22c55e" if c.get("chain_valid") else "#ef4444"
                cert_table_data.append([
                    Paragraph(str(c.get("stream_id", "N/A")), table_cell_style),
                    Paragraph(str(c.get("subject_cn", "N/A")), table_cell_style),
                    Paragraph(str(c.get("issuer_cn", "N/A")), table_cell_style),
                    Paragraph(f"<font color='{status_color}'><b>{c.get('chain_status', 'N/A')}</b></font>", table_cell_style),
                    Paragraph(f"{c.get('key_type', '')} {c.get('key_size', '')}b<br/>{c.get('signature_algorithm', '')}", table_cell_style),
                ])
            cert_table = Table(cert_table_data, colWidths=[65, 125, 125, 115, 110])
            cert_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f766e")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("PADDING", (0, 0), (-1, -1), 5),
            ]))
            story.append(cert_table)
        else:
            story.append(Paragraph("No TLS certificates observed in this traffic capture.", body_style))

        story.append(Spacer(1, 15))

        # 6. Detailed Vulnerability Findings
        story.append(Paragraph("3. Detailed Security Findings & Remediation Roadmap", h2_style))
        if findings:
            for idx, f in enumerate(findings[:10]):
                sev = f.get("severity", "LOW")
                sev_color = "#ef4444" if sev == "CRITICAL" else ("#f97316" if sev == "HIGH" else ("#eab308" if sev == "MEDIUM" else "#3b82f6"))
                
                finding_box_data = [
                    [
                        Paragraph(f"<font color='{sev_color}'><b>[{sev}] {f.get('rule_id', '')}: {f.get('title', '')}</b></font> (CVSS: {f.get('cvss_score', 0.0)})", ParagraphStyle("H", parent=table_cell_style, fontSize=9.5, fontName="Helvetica-Bold")),
                        Paragraph(f"Stream: {f.get('stream_id', 'N/A')}", ParagraphStyle("R", parent=table_cell_style, alignment=2))
                    ],
                    [
                        Paragraph(f"<b>Observation:</b> {f.get('description', '')}", table_cell_style),
                        Paragraph("", table_cell_style)
                    ],
                    [
                        Paragraph(f"<b>Remediation:</b> <font color='#0284c7'>{f.get('recommendation', '')}</font>", table_cell_style),
                        Paragraph("", table_cell_style)
                    ]
                ]
                f_table = Table(finding_box_data, colWidths=[420, 120])
                f_table.setStyle(TableStyle([
                    ("SPAN", (0, 1), (1, 1)),
                    ("SPAN", (0, 2), (1, 2)),
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                    ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#e2e8f0")),
                    ("LINELEFT", (0, 0), (0, -1), 3.5, colors.HexColor(sev_color)),
                    ("PADDING", (0, 0), (-1, -1), 5),
                ]))
                story.append(f_table)
                story.append(Spacer(1, 6))
        else:
            story.append(Paragraph("✅ No security vulnerabilities detected. All sessions adhere to cryptographic best practices.", body_style))

        # Build document
        doc.build(story)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        return pdf_bytes
