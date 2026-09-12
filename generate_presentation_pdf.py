#!/usr/bin/env python3
"""
Presentation PDF Generator for:
SDN-Based Honeypot Threat Detection & Secure Routing in Financial Networks
"""

import os
import sys

def generate_pdf():
    try:
        from reportlab.lib.pagesizes import letter, landscape
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors
        from reportlab.pdfgen import canvas
    except ImportError:
        print("[!] reportlab is not installed. Run: pip install reportlab")
        return

    output_filename = "SDN_Financial_Security_Presentation.pdf"
    doc = SimpleDocTemplate(
        output_filename,
        pagesize=landscape(letter),
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'MainTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=24,
        leading=28,
        textColor=colors.HexColor('#0f172a'),
        alignment=1
    )

    subtitle_style = ParagraphStyle(
        'Subtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=13,
        leading=16,
        textColor=colors.HexColor('#3b82f6'),
        alignment=1
    )

    slide_heading = ParagraphStyle(
        'SlideHeading',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=18,
        leading=22,
        textColor=colors.HexColor('#1e293b'),
        spaceAfter=12
    )

    body_style = ParagraphStyle(
        'SlideBody',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=11,
        leading=16,
        textColor=colors.HexColor('#334155')
    )

    bullet_style = ParagraphStyle(
        'SlideBullet',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10.5,
        leading=15,
        textColor=colors.HexColor('#1e293b')
    )

    code_style = ParagraphStyle(
        'CodeText',
        parent=styles['Code'],
        fontName='Courier',
        fontSize=9.5,
        leading=13,
        textColor=colors.HexColor('#0f172a')
    )

    story = []

    # ------------------ SLIDE 1: TITLE SLIDE ------------------
    story.append(Spacer(1, 60))
    story.append(Paragraph("🏦 SDN-Based Honeypot Threat Detection &<br/>Secure Routing for Financial Networks", title_style))
    story.append(Spacer(1, 16))
    story.append(Paragraph("Intelligent Intrusion Detection, Real-Time DDoS Mitigation & SDN Rerouting", subtitle_style))
    story.append(Spacer(1, 30))
    
    meta_data = [
        [Paragraph("<b>Domain:</b> Financial Network Security & SDN", body_style), Paragraph("<b>Frameworks:</b> Flask, Ryu/OpenFlow, Mininet", body_style)],
        [Paragraph("<b>ML Engine:</b> Isolation Forest & ExtraTree", body_style), Paragraph("<b>Architecture:</b> 4-Tier Software-Defined Network", body_style)]
    ]
    t_meta = Table(meta_data, colWidths=[330, 330])
    t_meta.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#cbd5e1')),
        ('PADDING', (0,0), (-1,-1), 10),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(t_meta)
    story.append(PageBreak())

    # ------------------ SLIDE 2: 4-TIER ARCHITECTURE ------------------
    story.append(Paragraph("🏗️ System Architecture: 4-Tier SDN Model", slide_heading))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#3b82f6'), spaceAfter=14))
    
    arch_rows = [
        [Paragraph("<b>Layer / Tier</b>", body_style), Paragraph("<b>Components</b>", body_style), Paragraph("<b>Role & Functionality</b>", body_style)],
        [Paragraph("<b>1. Network Edge</b>", bullet_style), Paragraph("Customer (10.0.0.1)<br/>Attacker (192.168.100.x)", bullet_style), Paragraph("Legitimate financial traffic & simulated DDoS botnet sources.", bullet_style)],
        [Paragraph("<b>2. Data Plane</b>", bullet_style), Paragraph("OpenFlow Switches (s1, s2, s3, s4)", bullet_style), Paragraph("High-speed packet forwarding and dynamic flow-mod rule enforcement.", bullet_style)],
        [Paragraph("<b>3. Control Plane</b>", bullet_style), Paragraph("SDN Ryu Controller<br/>(<code>flow_manager.py</code>)", bullet_style), Paragraph("Centralized topology visibility, reactive flow routing, and path computation.", bullet_style)],
        [Paragraph("<b>4. Application & ML</b>", bullet_style), Paragraph("ML Anomaly Detector<br/>Flask SPA Dashboard<br/>Honeypot Trap (10.0.0.5)", bullet_style), Paragraph("Unsupervised threat classification, real-time live telemetry, and attacker entrapment.", bullet_style)]
    ]
    t_arch = Table(arch_rows, colWidths=[130, 200, 350])
    t_arch.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f172a')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('PADDING', (0,0), (-1,-1), 8),
        ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#f8fafc')),
    ]))
    story.append(t_arch)
    story.append(PageBreak())

    # ------------------ SLIDE 3: THREAT DETECTION ENGINE ------------------
    story.append(Paragraph("🧠 Dual-Layer Threat Detection Engine", slide_heading))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#10b981'), spaceAfter=14))
    
    engine_text = """
    <b>1. Machine Learning Anomaly Detection (Isolation Forest):</b><br/>
    • Unsupervised learning trained on network flow statistics (packet rate, byte length, inter-arrival time).<br/>
    • Automatically flags unknown volumetric DDoS floods (HTTP Flood, SYN Flood, UDP Flood) with anomaly score -1.<br/><br/>
    <b>2. Deterministic Rule Matching:</b><br/>
    • Fast pre-filter for known IP blacklists, signature patterns, and unauthorized port access attempts.<br/>
    • Provides sub-millisecond classification for high-priority banking infrastructure protection.
    """
    story.append(Paragraph(engine_text, body_style))
    story.append(Spacer(1, 15))

    flow_box = [
        [Paragraph("<b>Packet In</b>", code_style), Paragraph("➔", body_style), Paragraph("<b>ML / Rule Engine</b>", code_style), Paragraph("➔", body_style), Paragraph("<b>SDN Threat Event</b>", code_style), Paragraph("➔", body_style), Paragraph("<b>Dynamic Reroute</b>", code_style)]
    ]
    t_flow = Table(flow_box, colWidths=[100, 20, 150, 20, 150, 20, 140])
    t_flow.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,0), colors.HexColor('#e0e7ff')),
        ('BACKGROUND', (2,0), (2,0), colors.HexColor('#fee2e2')),
        ('BACKGROUND', (4,0), (4,0), colors.HexColor('#fef3c7')),
        ('BACKGROUND', (6,0), (6,0), colors.HexColor('#dcfce7')),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('PADDING', (0,0), (-1,-1), 10),
    ]))
    story.append(t_flow)
    story.append(PageBreak())

    # ------------------ SLIDE 4: SDN SECURE REROUTING & HONEYPOT ------------------
    story.append(Paragraph("🛡️ Dynamic Secure Rerouting & Honeypot Decoy", slide_heading))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#8b5cf6'), spaceAfter=14))

    reroute_rows = [
        [Paragraph("<b>Operational State</b>", body_style), Paragraph("<b>Visual Indicator</b>", body_style), Paragraph("<b>Network Flow Behavior</b>", body_style)],
        [Paragraph("<b>State 1: Normal</b>", bullet_style), Paragraph("🟢 Emerald Stream", bullet_style), Paragraph("Customer (10.0.0.1) ➔ Switches (s1/s2) ➔ Bank Server (10.0.0.2). Direct low-latency path.", bullet_style)],
        [Paragraph("<b>State 2: Attack Detected</b>", bullet_style), Paragraph("🚨 Red Threat Alert", bullet_style), Paragraph("Attacker botnet flood identified by ML Anomaly engine. Bank link isolated.", bullet_style)],
        [Paragraph("<b>State 3: Secure Rerouting</b>", bullet_style), Paragraph("🔄 Purple Decoy Path", bullet_style), Paragraph("SDN controller pushes OpenFlow Flow-Mod rules: Attacker diverted to Honeypot (10.0.0.5:8000), Customer traffic remains 100% operational.", bullet_style)]
    ]
    t_reroute = Table(reroute_rows, colWidths=[150, 150, 380])
    t_reroute.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f172a')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('PADDING', (0,0), (-1,-1), 9),
        ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#f8fafc')),
    ]))
    story.append(t_reroute)
    story.append(PageBreak())

    # ------------------ SLIDE 5: RESULTS & VERIFICATION ------------------
    story.append(Paragraph("📊 Verification & Demonstration Results", slide_heading))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#3b82f6'), spaceAfter=14))

    results_text = """
    <b>Key Demonstration Achievements:</b><br/>
    • <b>Zero Downtime for Banking API:</b> Legitimate transactions processed continuously during active 14-burst botnet DDoS attacks.<br/>
    • <b>Automated Isolation:</b> Attacker IP addresses (192.168.100.101–114) automatically trapped in decoy honeypot VLAN without human intervention.<br/>
    • <b>Real-Time Live UI Synchronization:</b> Single Page Application dashboard updates stats, SVG animated particle paths, threat tables, and honeypot forensics in under 1 second.<br/>
    • <b>Comprehensive Forensics:</b> All attack signatures, request payloads, and flow modifications logged and exportable to CSV.
    """
    story.append(Paragraph(results_text, body_style))
    story.append(Spacer(1, 25))

    footer_p = Paragraph("<font color='#64748b'><i>Project: SDN-Based Honeypot Threat Detection & Secure Routing for Financial Networks</i></font>", ParagraphStyle('Footer', parent=styles['Normal'], alignment=1))
    story.append(footer_p)

    doc.build(story)
    print(f"[✓] Successfully generated presentation PDF: {output_filename}")

if __name__ == "__main__":
    generate_pdf()
