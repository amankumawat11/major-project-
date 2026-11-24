import io
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

def generate_scan_pdf_report(scan: dict, vulnerabilities: list) -> bytes:
    """
    Generates an executive, professional cybersecurity audit PDF report.
    """
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

    # Custom styles
    brand_blue = colors.HexColor("#0f172a")
    accent_cyan = colors.HexColor("#0284c7")
    crit_red = colors.HexColor("#dc2626")
    high_orange = colors.HexColor("#ea580c")
    med_yellow = colors.HexColor("#ca8a04")
    low_green = colors.HexColor("#16a34a")
    text_dark = colors.HexColor("#1e293b")
    text_muted = colors.HexColor("#64748b")

    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=22,
        leading=26,
        textColor=brand_blue
    )
    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=text_muted
    )
    h2_style = ParagraphStyle(
        'Heading2',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=16,
        textColor=accent_cyan,
        spaceBefore=12,
        spaceAfter=6
    )
    body_style = ParagraphStyle(
        'BodyDark',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=text_dark
    )
    body_bold = ParagraphStyle(
        'BodyBold',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9,
        leading=13,
        textColor=text_dark
    )
    code_snippet_style = ParagraphStyle(
        'CodeSnippet',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#334155")
    )

    story = []

    # Header / Title Block
    story.append(Paragraph("SecureExplain AI &mdash; Cybersecurity Audit Report", title_style))
    story.append(Paragraph("Automated Vulnerability Assessment & Generative AI Remediation", subtitle_style))
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=2, color=accent_cyan, spaceAfter=14))

    # Meta Info Table
    scan_date = scan.get("created_at")
    if isinstance(scan_date, datetime):
        scan_date_str = scan_date.strftime("%Y-%m-%d %H:%M:%S UTC")
    else:
        scan_date_str = str(scan_date or datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"))

    meta_data = [
        [
            Paragraph("<b>Target Domain:</b>", body_style),
            Paragraph(scan.get("target_domain", "N/A"), body_bold),
            Paragraph("<b>Security Score:</b>", body_style),
            Paragraph(f"{scan.get('security_score', 0)} / 100", body_bold)
        ],
        [
            Paragraph("<b>Target URL:</b>", body_style),
            Paragraph(scan.get("target_url", "N/A"), body_style),
            Paragraph("<b>Overall Risk Level:</b>", body_style),
            Paragraph(scan.get("risk_level", "UNKNOWN"), body_bold)
        ],
        [
            Paragraph("<b>Scan Mode:</b>", body_style),
            Paragraph(scan.get("scan_mode", "quick").capitalize(), body_style),
            Paragraph("<b>Scan Date:</b>", body_style),
            Paragraph(scan_date_str, body_style)
        ],
        [
            Paragraph("<b>Target IP:</b>", body_style),
            Paragraph(scan.get("target_ip") or "Resolved dynamically", body_style),
            Paragraph("<b>Scan Duration:</b>", body_style),
            Paragraph(f"{scan.get('scan_duration_seconds', 0.0)} seconds", body_style)
        ]
    ]

    meta_table = Table(meta_data, colWidths=[100, 170, 110, 160])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#e2e8f0")),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 12))

    # Executive Summary / AI Assessment
    story.append(Paragraph("1. Executive Summary & AI Assessment", h2_style))
    ai_assessment = scan.get("overall_ai_assessment") or "Automated scan performed across SSL/TLS, HTTP security headers, and domain parameters."
    story.append(Paragraph(ai_assessment, body_style))
    story.append(Spacer(1, 10))

    # Vulnerability Summary Counts
    crit_count = sum(1 for v in vulnerabilities if v.get("severity") == "CRITICAL")
    high_count = sum(1 for v in vulnerabilities if v.get("severity") == "HIGH")
    med_count = sum(1 for v in vulnerabilities if v.get("severity") == "MEDIUM")
    low_count = sum(1 for v in vulnerabilities if v.get("severity") == "LOW")

    story.append(Paragraph("2. Risk Severity Breakdown", h2_style))
    breakdown_data = [
        ["Total Findings", "Critical Risk", "High Risk", "Medium Risk", "Low Risk"],
        [str(len(vulnerabilities)), str(crit_count), str(high_count), str(med_count), str(low_count)]
    ]
    breakdown_table = Table(breakdown_data, colWidths=[108, 108, 108, 108, 108])
    breakdown_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BACKGROUND', (0, 1), (0, 1), colors.HexColor("#f1f5f9")),
        ('BACKGROUND', (1, 1), (1, 1), colors.HexColor("#fee2e2")),
        ('BACKGROUND', (2, 1), (2, 1), colors.HexColor("#ffedd5")),
        ('BACKGROUND', (3, 1), (3, 1), colors.HexColor("#fef9c3")),
        ('BACKGROUND', (4, 1), (4, 1), colors.HexColor("#dcfce7")),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(breakdown_table)
    story.append(Spacer(1, 14))

    # Detailed Findings Section
    story.append(Paragraph("3. Detailed Security Findings & AI Remediation", h2_style))

    if not vulnerabilities:
        story.append(Paragraph("No significant security vulnerabilities were identified during this assessment.", body_style))
    else:
        for idx, vuln in enumerate(vulnerabilities, 1):
            sev = vuln.get("severity", "LOW")
            if sev == "CRITICAL":
                sev_color = crit_red
            elif sev == "HIGH":
                sev_color = high_orange
            elif sev == "MEDIUM":
                sev_color = med_yellow
            else:
                sev_color = low_green

            finding_header = [
                [
                    Paragraph(f"<b>#{idx} {vuln.get('title')}</b>", ParagraphStyle('FH', parent=styles['Normal'], fontName='Helvetica-Bold', fontSize=10, textColor=colors.white)),
                    Paragraph(f"<b>{sev}</b>", ParagraphStyle('FS', parent=styles['Normal'], fontName='Helvetica-Bold', fontSize=9, textColor=colors.white, alignment=TA_RIGHT))
                ]
            ]
            fh_table = Table(finding_header, colWidths=[420, 120])
            fh_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), sev_color),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ]))

            detail_rows = [
                [Paragraph("<b>Category:</b>", body_style), Paragraph(vuln.get("category", "General"), body_style)],
                [Paragraph("<b>Technical Evidence:</b>", body_style), Paragraph(vuln.get("evidence") or "Observation noted during scan", body_style)],
                [Paragraph("<b>What does this mean?</b>", body_style), Paragraph(vuln.get("ai_explanation") or vuln.get("description", ""), body_style)],
                [Paragraph("<b>Why is it dangerous?</b>", body_style), Paragraph(vuln.get("ai_why_dangerous") or vuln.get("potential_impact", ""), body_style)],
                [Paragraph("<b>Remediation:</b>", body_style), Paragraph(vuln.get("ai_remediation_steps") or vuln.get("remediation_recommendation", ""), body_style)],
            ]

            code_ex = vuln.get("ai_code_example")
            if code_ex:
                code_text = code_ex.replace("\n", "<br/>").replace(" ", "&nbsp;")
                detail_rows.append([
                    Paragraph("<b>Configuration Fix:</b>", body_style),
                    Paragraph(code_text, code_snippet_style)
                ])

            dt_table = Table(detail_rows, colWidths=[130, 410])
            dt_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#e2e8f0")),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ]))

            story.append(KeepTogether([fh_table, dt_table, Spacer(1, 10)]))

    # Security Improvement Checklist
    story.append(Spacer(1, 8))
    story.append(Paragraph("4. Recommended Security Action Checklist", h2_style))
    checklist_text = (
        "&bull; <b>Deploy Strict Security Headers:</b> Configure Content-Security-Policy and HSTS in reverse proxy.<br/>"
        "&bull; <b>Enforce TLS 1.3:</b> Deprecate TLS 1.0 and 1.1; verify certificate renewal automation.<br/>"
        "&bull; <b>Secure All Cookies:</b> Add 'HttpOnly', 'Secure', and 'SameSite=Lax' to session identifiers.<br/>"
        "&bull; <b>Suppress Server Version Banners:</b> Disable 'Server' and 'X-Powered-By' fingerprinting headers.<br/>"
        "&bull; <b>Strengthen Email Authentication:</b> Publish strict SPF and DMARC DNS records.<br/>"
        "&bull; <b>Automate Dotfile Protection:</b> Block public HTTP access to '.env' and '.git' directories."
    )
    story.append(Paragraph(checklist_text, body_style))

    # Limitations & Disclaimer
    story.append(Spacer(1, 12))
    story.append(Paragraph("5. Limitations & Disclaimer", h2_style))
    disclaimer_text = (
        "This security assessment was generated automatically by <b>SecureExplain AI</b> using non-intrusive safe checks "
        "and Generative AI analysis. It does not replace a comprehensive manual penetration test or formal compliance audit. "
        "Absence of reported vulnerabilities does not guarantee complete security against all attack vectors. "
        "Scans should only be conducted on systems for which explicit authorization has been granted."
    )
    story.append(Paragraph(disclaimer_text, ParagraphStyle('Disc', parent=styles['Normal'], fontName='Helvetica-Oblique', fontSize=8, leading=11, textColor=text_muted)))

    doc.build(story)
    return buffer.getvalue()
