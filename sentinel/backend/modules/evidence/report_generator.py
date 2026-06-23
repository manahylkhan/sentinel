import json
from datetime import datetime
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
)

from config import settings


def _style(name, **kwargs):
    styles = getSampleStyleSheet()
    base = styles.get(name, styles["Normal"])
    return ParagraphStyle(name=f"custom_{name}", parent=base, **kwargs)


def generate_fir_report(incident: dict, timeline: list, iocs: list, evidence: list) -> bytes:
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=20*mm, rightMargin=20*mm, topMargin=20*mm, bottomMargin=20*mm)
    styles = getSampleStyleSheet()
    story = []

    title_style = _style("Title", fontSize=18, textColor=colors.HexColor("#1a1a2e"), spaceAfter=6)
    h1_style = _style("Heading1", fontSize=14, textColor=colors.HexColor("#16213e"), spaceAfter=4, spaceBefore=12)
    h2_style = _style("Heading2", fontSize=11, textColor=colors.HexColor("#0f3460"), spaceAfter=3, spaceBefore=8)
    normal_style = _style("Normal", fontSize=9, spaceAfter=3)
    small_style = _style("Normal", fontSize=8, textColor=colors.grey)

    def hr():
        return HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cccccc"), spaceAfter=6)

    # Header
    story.append(Paragraph("SENTINEL — Cybersecurity Incident Report", title_style))
    story.append(Paragraph(f"Prepared for: {settings.ORG_NAME}", h2_style))
    story.append(Paragraph(f"Report Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", small_style))
    story.append(Paragraph("CONFIDENTIAL — For authorized personnel only", small_style))
    story.append(hr())
    story.append(Spacer(1, 4))

    # 1. Incident Summary
    story.append(Paragraph("1. Incident Summary", h1_style))
    severity_color = {"critical": "#dc2626", "high": "#ea580c", "medium": "#d97706", "low": "#16a34a"}.get(incident.get("severity", "medium"), "#374151")
    summary_data = [
        ["Title", incident.get("title", "N/A")],
        ["Incident Type", incident.get("incident_type", "N/A").replace("_", " ").title()],
        ["Severity", incident.get("severity", "N/A").upper()],
        ["Status", incident.get("status", "N/A").replace("_", " ").title()],
        ["Date Reported", incident.get("created_at", "N/A")[:19].replace("T", " ") if incident.get("created_at") else "N/A"],
        ["Reporter", f"{incident.get('reporter_name', 'N/A')} ({incident.get('reporter_email', 'N/A')})"],
        ["Affected Systems", incident.get("affected_systems", "N/A")],
        ["PECA 2016 Reporting", "REQUIRED" if incident.get("peca_required") else "Not required"],
    ]
    t = Table(summary_data, colWidths=[50*mm, 120*mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e2e8f0")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("PADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t)

    # 2. Description
    story.append(Spacer(1, 6))
    story.append(Paragraph("2. Incident Description", h1_style))
    story.append(Paragraph(incident.get("description", "No description provided."), normal_style))

    # 3. Timeline
    story.append(Paragraph("3. Incident Timeline", h1_style))
    if timeline:
        tl_data = [["Date/Time (UTC)", "Action", "Detail", "By"]]
        for entry in timeline:
            ts = entry.get("created_at", "")[:19].replace("T", " ") if entry.get("created_at") else ""
            tl_data.append([ts, entry.get("action", ""), entry.get("detail", "")[:80], entry.get("created_by", "")])
        t = Table(tl_data, colWidths=[35*mm, 35*mm, 70*mm, 30*mm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e2e8f0")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("PADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(t)
    else:
        story.append(Paragraph("No timeline entries recorded.", normal_style))

    # 4. Indicators of Compromise
    story.append(Paragraph("4. Indicators of Compromise", h1_style))
    if iocs:
        ioc_data = [["Type", "Indicator", "Verdict", "Status"]]
        for ioc in iocs:
            ioc_data.append([
                ioc.get("indicator_type", "").upper(),
                ioc.get("indicator", "")[:50],
                ioc.get("verdict", "unknown").upper(),
                ioc.get("status", "active"),
            ])
        t = Table(ioc_data, colWidths=[20*mm, 90*mm, 30*mm, 30*mm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e2e8f0")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ]))
        story.append(t)
    else:
        story.append(Paragraph("No IOCs recorded.", normal_style))

    # 5. Evidence
    story.append(Paragraph("5. Evidence Collected", h1_style))
    if evidence:
        ev_data = [["File Name", "Size", "SHA-256 Hash", "Uploaded By", "Date"]]
        for ev in evidence:
            size_kb = f"{ev.get('file_size', 0) // 1024} KB"
            ev_data.append([
                ev.get("file_name", "")[:30],
                size_kb,
                ev.get("file_hash_sha256", "")[:24] + "...",
                ev.get("uploaded_by", ""),
                ev.get("created_at", "")[:10] if ev.get("created_at") else "",
            ])
        t = Table(ev_data, colWidths=[40*mm, 20*mm, 60*mm, 30*mm, 20*mm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e2e8f0")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ]))
        story.append(t)
    else:
        story.append(Paragraph("No evidence files uploaded.", normal_style))

    # 6. PECA / FIA
    story.append(Paragraph("6. Pakistan Legal Reporting Obligations", h1_style))
    if incident.get("peca_required"):
        story.append(Paragraph(f"<b>PECA 2016 Reporting Required:</b> {incident.get('peca_reason', '')}", normal_style))
        story.append(Paragraph("<b>FIA Cybercrime Wing Contact:</b>", normal_style))
        story.append(Paragraph("Website: report.fia.gov.pk", normal_style))
        story.append(Paragraph("Helpline: 0800-02345", normal_style))
        story.append(Paragraph("Email: cybercrime@fia.gov.pk", normal_style))
    else:
        story.append(Paragraph("PECA 2016 mandatory reporting does not appear to apply to this incident. Consult legal counsel to confirm.", normal_style))

    # 7. MITRE ATT&CK
    mitre = incident.get("mitre_techniques") or []
    if isinstance(mitre, str):
        try:
            mitre = json.loads(mitre)
        except Exception:
            mitre = []
    if mitre:
        story.append(Paragraph("7. MITRE ATT&CK Techniques Identified", h1_style))
        for tech in mitre:
            story.append(Paragraph(
                f"<b>{tech.get('technique_id')}</b> — {tech.get('technique_name')} ({tech.get('tactic')}) — Confidence: {tech.get('confidence', 'unknown')}",
                normal_style,
            ))

    # Footer
    story.append(Spacer(1, 10))
    story.append(hr())
    story.append(Paragraph(f"Generated by SENTINEL | {settings.ORG_NAME} | {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", small_style))
    story.append(Paragraph("This report is confidential and intended for authorized personnel only.", small_style))

    doc.build(story)
    return buf.getvalue()
