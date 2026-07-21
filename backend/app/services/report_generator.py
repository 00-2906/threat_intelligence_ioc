"""
PDF report generator for log-scan results.

Takes a LogScanReport (see log_scanner.py) and renders it into a
polished, downloadable PDF: session summary, then a detailed section
per malicious/suspicious IOC (risk score, LLM explanation, cited
MITRE ATT&CK techniques, nearest reference matches), plus a benign
count for completeness.
"""

import io
from datetime import datetime, timezone
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)

from app.services.log_scanner import LogScanReport, ScannedIOC

_styles = getSampleStyleSheet()

_TITLE = ParagraphStyle(
    "ReportTitle", parent=_styles["Title"], textColor=colors.HexColor("#1a1a2e")
)
_H2 = ParagraphStyle(
    "SectionHeading", parent=_styles["Heading2"], spaceBefore=18, spaceAfter=8
)
_IOC_HEADING_MALICIOUS = ParagraphStyle(
    "IOCHeadingMalicious",
    parent=_styles["Heading3"],
    textColor=colors.HexColor("#b91c1c"),
    spaceBefore=14,
)
_IOC_HEADING_SUSPICIOUS = ParagraphStyle(
    "IOCHeadingSuspicious",
    parent=_styles["Heading3"],
    textColor=colors.HexColor("#c2410c"),
    spaceBefore=14,
)
_BODY = ParagraphStyle("ReportBody", parent=_styles["Normal"], spaceAfter=6, leading=14)
_LABEL = ParagraphStyle(
    "FieldLabel", parent=_styles["Normal"], textColor=colors.HexColor("#555555"), fontSize=9
)
_MONO = ParagraphStyle(
    "MonoContext",
    parent=_styles["Normal"],
    fontName="Courier",
    fontSize=8,
    backColor=colors.HexColor("#f4f4f4"),
    borderPadding=4,
)


def _esc(text: str) -> str:
    """Escape user/LLM-generated text so it can't break ReportLab's XML parser."""
    return escape(text or "")


def _ioc_section(item: ScannedIOC, heading_style: ParagraphStyle) -> list:
    story = []
    story.append(
        Paragraph(f"{_esc(item.ioc_type.upper())}: {_esc(item.value)}", heading_style)
    )
    story.append(
        Paragraph(
            f"Line {item.line_number} &nbsp;&bull;&nbsp; "
            f"Risk score: {item.score.malicious_score * 100:.1f}/100 &nbsp;&bull;&nbsp; "
            f"Verdict: {_esc(item.score.verdict.upper())}",
            _LABEL,
        )
    )
    story.append(Spacer(1, 4))

    if item.context:
        story.append(Paragraph("Log context:", _LABEL))
        story.append(Paragraph(_esc(item.context), _MONO))
        story.append(Spacer(1, 6))

    if item.explanation:
        story.append(Paragraph("AI explanation:", _LABEL))
        story.append(Paragraph(_esc(item.explanation), _BODY))

    if item.cited_techniques:
        techniques = ", ".join(_esc(t) for t in item.cited_techniques)
        story.append(Paragraph(f"<b>MITRE ATT&amp;CK techniques:</b> {techniques}", _BODY))

    if item.score.neighbors:
        story.append(Paragraph("Nearest known reference matches:", _LABEL))
        rows = [["Label", "Similarity", "Reference"]]
        for n in item.score.neighbors[:3]:
            rows.append([_esc(n.label), f"{n.similarity:.2f}", _esc(n.text[:90])])
        table = Table(rows, colWidths=[0.8 * inch, 0.8 * inch, 4.2 * inch])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e5e7eb")),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        story.append(table)

    story.append(Spacer(1, 10))
    return story


def generate_report_pdf(report: LogScanReport) -> io.BytesIO:
    """
    Render a LogScanReport into a PDF and return it as an in-memory
    BytesIO buffer, ready to stream in a FastAPI response.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
        title="IOC Scanner Threat Report",
    )

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    story = []

    story.append(Paragraph("IOC Scanner — Threat Intelligence Report", _TITLE))
    story.append(Paragraph(f"Generated {generated_at}", _LABEL))
    story.append(Spacer(1, 16))

    story.append(Paragraph("Summary", _H2))
    story.append(Paragraph(_esc(report.summary()), _BODY))
    story.append(Spacer(1, 8))

    summary_rows = [
        ["Total lines scanned", str(report.total_lines_scanned)],
        ["Total IOCs found", str(report.total_iocs_found)],
        ["Malicious", str(len(report.malicious))],
        ["Suspicious", str(len(report.suspicious))],
        ["Benign", str(len(report.benign))],
    ]
    summary_table = Table(summary_rows, colWidths=[2.5 * inch, 3.5 * inch])
    summary_table.setStyle(
        TableStyle(
            [
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f4f4f4")),
            ]
        )
    )
    story.append(summary_table)

    if report.malicious:
        story.append(PageBreak())
        story.append(Paragraph("Malicious Indicators", _H2))
        for item in report.malicious:
            story.extend(_ioc_section(item, _IOC_HEADING_MALICIOUS))

    if report.suspicious:
        story.append(Paragraph("Suspicious Indicators", _H2))
        for item in report.suspicious:
            story.extend(_ioc_section(item, _IOC_HEADING_SUSPICIOUS))

    if report.benign:
        story.append(Paragraph("Benign Indicators", _H2))
        story.append(
            Paragraph(
                f"{len(report.benign)} indicator(s) scored below the suspicious "
                f"threshold and were not flagged. Values: "
                + ", ".join(_esc(b.value) for b in report.benign[:25])
                + (" ..." if len(report.benign) > 25 else ""),
                _BODY,
            )
        )

    doc.build(story)
    buffer.seek(0)
    return buffer