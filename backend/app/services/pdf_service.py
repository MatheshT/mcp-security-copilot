from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from datetime import datetime
import io
from typing import Dict, Optional, List

class PDFReportService:
    """Enhanced service for generating professional PDF reports"""
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Setup custom paragraph styles"""
        # Title style
        if 'ReportTitle' not in self.styles:
            self.styles.add(ParagraphStyle(
                name='ReportTitle',
                parent=self.styles['Heading1'],
                fontSize=28,
                textColor=colors.HexColor('#0a6b8f'),
                alignment=TA_CENTER,
                spaceAfter=20,
                fontName='Helvetica-Bold'
            ))
        
        # Subtitle style
        if 'ReportSubtitle' not in self.styles:
            self.styles.add(ParagraphStyle(
                name='ReportSubtitle',
                parent=self.styles['Normal'],
                fontSize=14,
                textColor=colors.HexColor('#4a6a7a'),
                alignment=TA_CENTER,
                spaceAfter=30,
                fontName='Helvetica'
            ))
        
        # Section header style
        if 'SectionHeader' not in self.styles:
            self.styles.add(ParagraphStyle(
                name='SectionHeader',
                parent=self.styles['Heading2'],
                fontSize=18,
                textColor=colors.HexColor('#1a3a4a'),
                spaceBefore=20,
                spaceAfter=12,
                fontName='Helvetica-Bold'
            ))
        
        # Subsection header
        if 'SubSectionHeader' not in self.styles:
            self.styles.add(ParagraphStyle(
                name='SubSectionHeader',
                parent=self.styles['Heading3'],
                fontSize=14,
                textColor=colors.HexColor('#2a4a5a'),
                spaceBefore=12,
                spaceAfter=8,
                fontName='Helvetica-Bold'
            ))
        
        # Body text - update if exists, add if not
        if 'BodyText' in self.styles:
            self.styles['BodyText'].fontSize = 11
            self.styles['BodyText'].leading = 16
            self.styles['BodyText'].spaceAfter = 8
            self.styles['BodyText'].fontName = 'Helvetica'
        else:
            self.styles.add(ParagraphStyle(
                name='BodyText',
                parent=self.styles['Normal'],
                fontSize=11,
                leading=16,
                spaceAfter=8,
                fontName='Helvetica'
            ))
        
        # Small text for metadata
        if 'MetaText' not in self.styles:
            self.styles.add(ParagraphStyle(
                name='MetaText',
                parent=self.styles['Normal'],
                fontSize=9,
                textColor=colors.HexColor('#6a8a9a'),
                alignment=TA_CENTER
        ))
    
    def generate_report(self, alert_id: str, data: Dict, format: str = "A4") -> bytes:
        """Generate PDF report for an alert"""
        buffer = io.BytesIO()
        
        # Select page size
        page_size = A4 if format == "A4" else letter
        
        doc = SimpleDocTemplate(
            buffer,
            pagesize=page_size,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72,
            title=f"SOC Report - {alert_id}",
            author="SOC Security Copilot"
        )
        
        # Build the document
        story = []
        
        # Add header
        story.extend(self._create_header())
        
        # Title section
        story.append(Paragraph("Security Incident Investigation Report", self.styles['ReportTitle']))
        story.append(Paragraph(f"Alert ID: {alert_id}", self.styles['ReportSubtitle']))
        story.append(Spacer(1, 0.25*inch))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#d0d7dd')))
        story.append(Spacer(1, 0.25*inch))
        
        # Executive Summary
        story.extend(self._create_executive_summary(data))
        
        # Alert Information
        story.extend(self._create_alert_information(data))
        
        # AI Analysis
        story.extend(self._create_ai_analysis(data))
        
        # Indicators of Compromise
        if data.get('ioc'):
            story.extend(self._create_ioc_section(data['ioc']))
        
        # Threat Intelligence
        if data.get('threat_intelligence'):
            story.extend(self._create_threat_intelligence(data['threat_intelligence']))
        
        # MITRE ATT&CK Mapping
        if data.get('mitre_mapping'):
            story.extend(self._create_mitre_mapping(data['mitre_mapping']))
        
        # Recommendations
        if data.get('recommendations'):
            story.extend(self._create_recommendations(data['recommendations']))
        
        # Timeline
        story.extend(self._create_timeline(data))
        
        # Footer
        story.extend(self._create_footer())
        
        # Build the document
        doc.build(story)
        
        buffer.seek(0)
        return buffer.getvalue()
    
    def _create_header(self):
        """Create report header with company branding"""
        story = []
        
        header_style = ParagraphStyle(
            'HeaderStyle',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor('#2a4a5a'),
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )
        
        story.append(Paragraph("SOC SECURITY COPILOT", header_style))
        story.append(Paragraph("Enterprise Security Operations Center", self.styles['MetaText']))
        story.append(Spacer(1, 0.1*inch))
        story.append(HRFlowable(width="80%", thickness=1, color=colors.HexColor('#d0d7dd')))
        story.append(Spacer(1, 0.2*inch))
        
        return story
    
    def _create_executive_summary(self, data: Dict):
        """Create executive summary section"""
        story = []
        story.append(Paragraph("Executive Summary", self.styles['SectionHeader']))
        
        summary_text = data.get('summary', 'No executive summary available.')
        story.append(Paragraph(summary_text, self.styles['BodyText']))
        
        # Key metrics in a table
        metrics = [
            ['Severity', data.get('severity', 'N/A')],
            ['Status', data.get('status', 'N/A')],
            ['Attack Type', data.get('attack_type', 'N/A')],
            ['Affected Host', data.get('host', 'N/A')],
            ['Detection Time', data.get('timestamp', 'N/A')],
        ]
        
        table = Table(metrics, colWidths=[2*inch, 3.5*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f0f5f9')),
            ('BACKGROUND', (1, 0), (1, -1), colors.white),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#1a3a4a')),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#d0d7dd')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        
        story.append(table)
        story.append(Spacer(1, 0.25*inch))
        
        return story
    
    def _create_alert_information(self, data: Dict):
        """Create alert information section"""
        story = []
        story.append(Paragraph("Alert Details", self.styles['SectionHeader']))
        
        details = [
            ['Alert ID', data.get('alert_id', 'N/A')],
            ['Severity', data.get('severity', 'N/A')],
            ['Attack Type', data.get('attack_type', 'N/A')],
            ['Affected Host', data.get('host', 'N/A')],
            ['Timestamp', data.get('timestamp', 'N/A')],
            ['Status', data.get('status', 'N/A')],
            ['Analyst', data.get('analyst', 'System')],
            ['Source IP', data.get('source_ip', 'N/A')],
            ['Destination IP', data.get('destination_ip', 'N/A')],
        ]
        
        table = Table(details, colWidths=[2*inch, 3.5*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f0f5f9')),
            ('BACKGROUND', (1, 0), (1, -1), colors.white),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#1a3a4a')),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#d0d7dd')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        
        story.append(table)
        story.append(Spacer(1, 0.25*inch))
        
        return story
    
    def _create_ai_analysis(self, data: Dict):
        """Create AI analysis section"""
        story = []
        story.append(Paragraph("AI-Powered Analysis", self.styles['SectionHeader']))
        
        analysis = data.get('ai_analysis', 'No AI analysis available.')
        story.append(Paragraph(analysis, self.styles['BodyText']))
        story.append(Spacer(1, 0.25*inch))
        
        return story
    
    def _create_ioc_section(self, iocs: List[str]):
        """Create IOC section"""
        story = []
        story.append(Paragraph("Indicators of Compromise (IOCs)", self.styles['SectionHeader']))
        
        # Create a table for IOCs
        ioc_data = [['Type', 'Indicator']]
        for ioc in iocs:
            if ioc.startswith('http'):
                ioc_type = 'URL'
            elif '.' in ioc and not any(c.isalpha() for c in ioc.replace('.', '')):
                ioc_type = 'IP Address'
            elif len(ioc) > 30:
                ioc_type = 'Hash'
            else:
                ioc_type = 'Domain'
            ioc_data.append([ioc_type, ioc])
        
        if len(ioc_data) > 1:
            table = Table(ioc_data, colWidths=[1.5*inch, 4*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2a4a5a')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#d0d7dd')),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('PADDING', (0, 0), (-1, -1), 6),
                ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                ('ALTERNATE_BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8fafc')),
            ]))
            story.append(table)
        else:
            story.append(Paragraph("No IOCs identified.", self.styles['BodyText']))
        
        story.append(Spacer(1, 0.25*inch))
        return story
    
    def _create_threat_intelligence(self, ti_data: Dict):
        """Create threat intelligence section"""
        story = []
        story.append(Paragraph("Threat Intelligence", self.styles['SectionHeader']))
        
        ti_text = f"""
        <b>Threat Actor:</b> {ti_data.get('actor', 'Unknown')}<br/>
        <b>Confidence Level:</b> {ti_data.get('confidence', 'N/A')}<br/>
        <b>Associated Tactics:</b> {', '.join(ti_data.get('tactics', ['N/A']))}<br/>
        <b>Related Campaigns:</b> {', '.join(ti_data.get('campaigns', ['N/A']))}
        """
        story.append(Paragraph(ti_text, self.styles['BodyText']))
        story.append(Spacer(1, 0.25*inch))
        
        return story
    
    def _create_mitre_mapping(self, mitre_data: Dict):
        """Create MITRE ATT&CK mapping section"""
        story = []
        story.append(Paragraph("MITRE ATT&CK Mapping", self.styles['SectionHeader']))
        
        mitre_text = f"""
        <b>Technique ID:</b> {mitre_data.get('technique_id', 'N/A')}<br/>
        <b>Technique Name:</b> {mitre_data.get('technique_name', 'N/A')}<br/>
        <b>Tactic:</b> {mitre_data.get('tactic', 'N/A')}<br/>
        <b>Description:</b> {mitre_data.get('description', 'N/A')}
        """
        story.append(Paragraph(mitre_text, self.styles['BodyText']))
        story.append(Spacer(1, 0.25*inch))
        
        return story
    
    def _create_recommendations(self, recommendations: List[str]):
        """Create recommendations section"""
        story = []
        story.append(Paragraph("Recommendations & Next Steps", self.styles['SectionHeader']))
        
        if isinstance(recommendations, list):
            for i, rec in enumerate(recommendations, 1):
                story.append(Paragraph(f"{i}. {rec}", self.styles['BodyText']))
        else:
            story.append(Paragraph(str(recommendations), self.styles['BodyText']))
        
        story.append(Spacer(1, 0.25*inch))
        return story
    
    def _create_timeline(self, data: Dict):
        """Create investigation timeline section"""
        story = []
        story.append(Paragraph("Investigation Timeline", self.styles['SectionHeader']))
        
        # In production, this would come from actual timeline data
        timeline_data = [
            ['Time', 'Event'],
            [data.get('timestamp', 'N/A'), 'Alert Detected'],
            [data.get('timestamp', 'N/A'), 'AI Analysis Initiated'],
            [data.get('timestamp', 'N/A'), 'Threat Intelligence Correlation'],
            [data.get('timestamp', 'N/A'), 'Investigation In Progress']
        ]
        
        table = Table(timeline_data, colWidths=[2*inch, 3.5*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2a4a5a')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#d0d7dd')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('PADDING', (0, 0), (-1, -1), 6),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('ALTERNATE_BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8fafc')),
        ]))
        
        story.append(table)
        story.append(Spacer(1, 0.25*inch))
        
        return story
    
    def _create_footer(self):
        """Create report footer with metadata"""
        story = []
        story.append(Spacer(1, 0.5*inch))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#d0d7dd')))
        story.append(Spacer(1, 0.1*inch))
        
        footer_text = f"""
        <b>Report Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}<br/>
        <b>Classification:</b> CONFIDENTIAL - For Security Operations Use Only<br/>
        <b>System:</b> SOC Security Copilot v1.0.0
        """
        story.append(Paragraph(footer_text, self.styles['MetaText']))
        story.append(Spacer(1, 0.1*inch))
        
        return story