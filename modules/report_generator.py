from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.colors import HexColor, black, white
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from datetime import datetime
import os

# Renkler
RED = HexColor("#f85149")
GREEN = HexColor("#3fb950")
BLUE = HexColor("#58a6ff")
ORANGE = HexColor("#f0883e")
YELLOW = HexColor("#d29922")
DARK = HexColor("#0d1117")
GRAY = HexColor("#8b949e")
LIGHT_GRAY = HexColor("#161b22")
WHITE = white

# Font
font_path = "/System/Library/Fonts/Supplemental/Arial Unicode.ttf"
if os.path.exists(font_path):
    pdfmetrics.registerFont(TTFont("Arial", font_path))
    FONT = "Arial"
else:
    FONT = "Helvetica"

def get_risk_color(level):
    colors = {"CRITICAL": RED, "HIGH": ORANGE, "MEDIUM": YELLOW, "LOW": GREEN}
    return colors.get(level, GRAY)

def generate_forensics_report(evidence, timeline, ip_results, threats, output_path="reports/forensics_report.pdf"):
    os.makedirs("reports", exist_ok=True)

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=2*cm,
        leftMargin=2*cm,
        topMargin=2*cm,
        bottomMargin=2*cm
    )

    styles = getSampleStyleSheet()
    elements = []

    title_style = ParagraphStyle("Title", parent=styles["Normal"], fontSize=22, textColor=BLUE, spaceAfter=6, fontName=FONT)
    subtitle_style = ParagraphStyle("Subtitle", parent=styles["Normal"], fontSize=11, textColor=GRAY, spaceAfter=20, fontName=FONT)
    section_style = ParagraphStyle("Section", parent=styles["Normal"], fontSize=13, textColor=BLUE, spaceBefore=16, spaceAfter=8, fontName=FONT)
    normal_style = ParagraphStyle("Normal2", parent=styles["Normal"], fontSize=9, textColor=black, spaceAfter=4, fontName=FONT)
    alert_style = ParagraphStyle("Alert", parent=styles["Normal"], fontSize=9, textColor=RED, spaceAfter=4, fontName=FONT)

    # Başlık
    elements.append(Paragraph("CloudForensics - AWS Dijital Adli Analiz Raporu", title_style))
    elements.append(Paragraph(f"Olusturulma: {datetime.now().strftime('%d.%m.%Y %H:%M')} | Son {evidence.get('time_range_hours', 24)} saat analiz edildi", subtitle_style))

    # Risk özeti tablosu
    risk_color = get_risk_color(threats.get("risk_level", "LOW"))
    summary_data = [
        ["Risk Skoru", "Risk Seviyesi", "Toplam Olay", "Supheliler"],
        [
            str(threats.get("risk_score", 0)) + "/100",
            threats.get("risk_level", "LOW"),
            str(evidence.get("total_events", 0)),
            str(len(threats.get("anomalies", [])))
        ]
    ]
    summary_table = Table(summary_data, colWidths=[4*cm, 4*cm, 4*cm, 4*cm])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), DARK),
        ("TEXTCOLOR", (0, 0), (-1, 0), BLUE),
        ("FONTNAME", (0, 0), (-1, -1), FONT),
        ("FONTSIZE", (0, 0), (-1, 0), 10),
        ("BACKGROUND", (0, 1), (-1, -1), LIGHT_GRAY),
        ("TEXTCOLOR", (0, 1), (0, 1), risk_color),
        ("TEXTCOLOR", (1, 1), (1, 1), risk_color),
        ("TEXTCOLOR", (2, 1), (-1, -1), WHITE),
        ("FONTSIZE", (0, 1), (-1, -1), 12),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ROWHEIGHT", (0, 0), (-1, -1), 0.9*cm),
        ("GRID", (0, 0), (-1, -1), 0.5, GRAY),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 0.5*cm))

    # Saldiri pattern
    if threats.get("attack_patterns"):
        elements.append(Paragraph("Tespit Edilen Saldiri Patternleri", section_style))
        for pattern in threats["attack_patterns"]:
            color = get_risk_color(pattern["severity"])
            elements.append(Paragraph(
                f"[{pattern['severity']}] {pattern['description']} — {pattern['total_occurrences']} olay",
                ParagraphStyle("p", parent=styles["Normal"], fontSize=9, textColor=color, fontName=FONT, spaceAfter=3)
            ))

    # Anomaliler
    if threats.get("anomalies"):
        elements.append(Paragraph("Tespit Edilen Anomaliler", section_style))
        for anomaly in threats["anomalies"]:
            elements.append(Paragraph(f"• {anomaly['description']}", alert_style))

    # Suphelı IP'ler
    suspicious_ips = [(ip, d) for ip, d in ip_results.items() if d.get("threat_score", 0) > 0]
    if suspicious_ips:
        elements.append(Paragraph("Suphelı IP Adresleri", section_style))
        ip_data = [["IP Adresi", "Ulke", "ISP", "Tehdit"]]
        for ip, data in suspicious_ips[:10]:
            ip_data.append([
                ip,
                data.get("country", "Bilinmiyor"),
                data.get("isp", "Bilinmiyor")[:30],
                ", ".join(data.get("threat_types", ["Bilinmiyor"]))
            ])
        ip_table = Table(ip_data, colWidths=[3.5*cm, 3*cm, 5*cm, 4.5*cm])
        ip_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), DARK),
            ("TEXTCOLOR", (0, 0), (-1, 0), BLUE),
            ("FONTNAME", (0, 0), (-1, -1), FONT),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("BACKGROUND", (0, 1), (-1, -1), WHITE),
            ("TEXTCOLOR", (0, 1), (-1, -1), black),
            ("GRID", (0, 0), (-1, -1), 0.5, GRAY),
            ("ROWHEIGHT", (0, 0), (-1, -1), 0.65*cm),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ]))
        elements.append(ip_table)

    # Suphelı olaylar
    suspicious_events = [e for e in timeline.get("events", []) if e.get("suspicious")]
    if suspicious_events:
        elements.append(Paragraph(f"Suphelı Olaylar ({len(suspicious_events)} adet)", section_style))
        event_data = [["Zaman", "Olay", "Kullanici", "IP"]]
        for event in suspicious_events[:20]:
            event_data.append([
                event.get("time", "")[:19],
                event.get("event_name", ""),
                event.get("username", ""),
                event.get("source_ip", "")
            ])
        event_table = Table(event_data, colWidths=[4*cm, 4.5*cm, 4*cm, 3.5*cm])
        event_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), DARK),
            ("TEXTCOLOR", (0, 0), (-1, 0), BLUE),
            ("FONTNAME", (0, 0), (-1, -1), FONT),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("BACKGROUND", (0, 1), (-1, -1), WHITE),
            ("TEXTCOLOR", (0, 1), (-1, -1), black),
            ("GRID", (0, 0), (-1, -1), 0.5, GRAY),
            ("ROWHEIGHT", (0, 0), (-1, -1), 0.6*cm),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ]))
        elements.append(event_table)

    # Footer
    elements.append(Spacer(1, 1*cm))
    footer_style = ParagraphStyle("Footer", parent=styles["Normal"], fontSize=8, textColor=GRAY, alignment=1, fontName=FONT)
    elements.append(Paragraph("CloudForensics — github.com/kaansoyturk/cloudforensics", footer_style))

    doc.build(elements)
    print(f"PDF rapor olusturuldu: {output_path}")
    return output_path