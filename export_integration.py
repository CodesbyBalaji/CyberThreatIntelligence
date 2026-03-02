"""
Export and Integration module for the CyberShield Platform.
Handles STIX 2.1 export, PDF executive report generation, and TAXII logic helpers.
"""

from stix2 import Indicator, Bundle, Identity
import json
import uuid
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
import io

class ExtractorExportManager:
    def __init__(self, storage):
        self.storage = storage
        self.identity = Identity(
            id=f"identity--{uuid.uuid4()}",
            name="CyberShield Enterprise CTI",
            identity_class="system"
        )

    def _get_stix_pattern(self, ioc_type, value):
        ioc_type = ioc_type.lower()
        if ioc_type in ['ip', 'ipv4']:
            return f"[ipv4-addr:value = '{value}']"
        elif ioc_type == 'domain':
            return f"[domain-name:value = '{value}']"
        elif ioc_type == 'url':
            return f"[url:value = '{value}']"
        elif ioc_type in ['md5', 'sha1', 'sha256']:
            return f"[file:hashes.'{ioc_type.upper()}' = '{value}']"
        elif ioc_type == 'email':
            return f"[email-addr:value = '{value}']"
        else:
            return f"[cyber-observable:value = '{value}']"

    def export_stix2_iocs(self, iocs):
        """Convert a list of IOC dictionaries to a STIX 2.1 Bundle"""
        stix_objects = [self.identity]
        
        for ioc in iocs:
            pattern = self._get_stix_pattern(ioc.get('type', 'unknown'), ioc.get('value', ''))
            indicator = Indicator(
                id=f"indicator--{uuid.uuid4()}",
                name=f"Malicious {ioc.get('type', 'Indicator')}: {ioc.get('value', '')}",
                pattern=pattern,
                pattern_type="stix",
                created_by_ref=self.identity.id,
                labels=[ioc.get('type', 'indicator')],
                confidence=int((ioc.get('confidence', 0.5) * 100))
            )
            stix_objects.append(indicator)
            
        bundle = Bundle(objects=stix_objects)
        return bundle.serialize()

    def generate_pdf_report(self, report_data: dict) -> bytes:
        """Generate a PDF Executive Report from LLM report string or structured data"""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=18)
        
        styles = getSampleStyleSheet()
        title_style = styles['Heading1']
        title_style.textColor = colors.HexColor('#002b5e')
        
        h2_style = styles['Heading2']
        h2_style.textColor = colors.HexColor('#005b9f')
        
        normal_style = styles['Normal']
        normal_style.fontSize = 11
        normal_style.leading = 14
        
        elements = []
        
        # Title
        elements.append(Paragraph("CyberShield Executive Threat Report", title_style))
        elements.append(Spacer(1, 12))
        
        # Date
        elements.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}", normal_style))
        elements.append(Spacer(1, 24))
        
        # Content Parsing
        report_text = report_data.get('report', '')
        
        # Fallback text if nothing is generated
        if not report_text:
            report_text = "No report data provided."
            
        for line in report_text.split('\n'):
            line = line.strip()
            if not line:
                elements.append(Spacer(1, 12))
                continue
                
            if line.startswith('#'):
                header_level = len(line.split(' ')[0])
                text = line[header_level:].strip()
                style = styles[f'Heading{min(header_level, 4)}']
                elements.append(Paragraph(text, style))
            elif line.startswith('-') or line.startswith('*'):
                elements.append(Paragraph(line, normal_style))
            else:
                elements.append(Paragraph(line, normal_style))
                
        doc.build(elements)
        buffer.seek(0)
        return buffer.getvalue()
