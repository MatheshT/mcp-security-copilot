from fastapi import APIRouter, HTTPException, Response, Query
from typing import Optional
import json
import random
from datetime import datetime
from ..services.pdf_service import PDFReportService
from ..services.dashboard_service import dashboard_service
from ..schemas import ReportData, SeverityLevel, InvestigationStatus
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/report", tags=["report"])
pdf_service = PDFReportService()

@router.get("/{alert_id}/pdf")
async def generate_pdf_report(
    alert_id: str,
    format: str = Query("A4", regex="^(A4|Letter)$")
):
    """Generate PDF report for an alert"""
    try:
        # Try to get real investigation data
        investigation = dashboard_service.get_investigation_by_id(alert_id)
        
        if investigation:
            # Use real data
            report_data = ReportData(
                alert_id=investigation.alert_id,
                severity=investigation.severity,
                attack_type=investigation.attack_type,
                host=investigation.host,
                timestamp=investigation.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
                status=investigation.status,
                ioc=investigation.ioc,
                summary=investigation.summary or "Investigation in progress",
                analyst=investigation.analyst or "System",
                source_ip=investigation.source_ip,
                destination_ip=investigation.destination_ip
            )
        else:
            # Generate mock data
            report_data = get_mock_report_data(alert_id)
        
        # Add AI analysis
        report_data.ai_analysis = await generate_ai_analysis(report_data)
        
        # Add threat intelligence
        report_data.threat_intelligence = generate_threat_intelligence()
        
        # Add MITRE mapping
        report_data.mitre_mapping = generate_mitre_mapping(report_data.attack_type)
        
        # Add recommendations
        report_data.recommendations = await dashboard_service.get_recommendations(alert_id)
        
        # Generate PDF
        pdf_content = pdf_service.generate_report(alert_id, report_data.dict(), format)
        
        return Response(
            content=pdf_content,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=SOC_Report_{alert_id}_{datetime.now().strftime('%Y%m%d')}.pdf"
            }
        )
    except Exception as e:
        logger.error(f"Error generating PDF report: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{alert_id}/json")
async def get_report_json(alert_id: str):
    """Get report data in JSON format"""
    try:
        investigation = dashboard_service.get_investigation_by_id(alert_id)
        if investigation:
            report_data = ReportData(
                alert_id=investigation.alert_id,
                severity=investigation.severity,
                attack_type=investigation.attack_type,
                host=investigation.host,
                timestamp=investigation.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
                status=investigation.status,
                ioc=investigation.ioc,
                summary=investigation.summary,
                analyst=investigation.analyst,
                source_ip=investigation.source_ip,
                destination_ip=investigation.destination_ip
            )
        else:
            report_data = get_mock_report_data(alert_id)
        
        return report_data.dict()
    except Exception as e:
        logger.error(f"Error getting report JSON: {e}")
        raise HTTPException(status_code=500, detail=str(e))

async def generate_ai_analysis(data: ReportData) -> str:
    """Generate AI analysis for the report"""
    # This would integrate with your LLM client
    analysis_templates = [
        f"The investigation has identified a {data.severity.value.lower()} severity {data.attack_type} attack targeting {data.host}. Initial analysis suggests the attack vector involves multiple stages including reconnaissance, initial access, and lateral movement. The attacker appears to be using advanced evasion techniques to avoid detection.",
        f"Analysis of the {data.attack_type} incident on {data.host} reveals a sophisticated attack pattern. The threat actor has demonstrated advanced capabilities in maintaining persistence and evading detection. Recommended immediate containment actions are critical to prevent further compromise.",
        f"This {data.severity.value.lower()} severity alert indicates a {data.attack_type} attack against {data.host}. The attack chain suggests a coordinated effort with potential ties to advanced persistent threat groups. Immediate investigation and response are required."
    ]
    return random.choice(analysis_templates)

def generate_threat_intelligence() -> dict:
    """Generate threat intelligence data"""
    actors = ["APT-29", "Lazarus Group", "FIN7", "APT-41", "UNC2452", "Unknown"]
    campaigns = ["Operation Shadow", "Campaign 2026-Q3", "Ghost Protocol", "Silent Skies"]
    tactics = ["Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion"]
    
    return {
        "actor": random.choice(actors),
        "confidence": random.choice(["High", "Medium", "Low"]),
        "tactics": random.sample(tactics, 3),
        "campaigns": random.sample(campaigns, 2)
    }

def generate_mitre_mapping(attack_type: str) -> dict:
    """Generate MITRE ATT&CK mapping based on attack type"""
    mappings = {
        "Phishing": {
            "technique_id": "T1566",
            "technique_name": "Phishing",
            "tactic": "Initial Access",
            "description": "Spearphishing email with malicious attachment or link"
        },
        "Malware": {
            "technique_id": "T1204",
            "technique_name": "User Execution",
            "tactic": "Execution",
            "description": "Execution of malicious file or script"
        },
        "Ransomware": {
            "technique_id": "T1486",
            "technique_name": "Data Encrypted for Impact",
            "tactic": "Impact",
            "description": "Encryption of critical files for ransom"
        },
        "DDoS": {
            "technique_id": "T1498",
            "technique_name": "Network Denial of Service",
            "tactic": "Impact",
            "description": "Flooding network with malicious traffic"
        },
        "Data Exfiltration": {
            "technique_id": "T1048",
            "technique_name": "Exfiltration Over Alternative Protocol",
            "tactic": "Exfiltration",
            "description": "Unauthorized transfer of sensitive data"
        }
    }
    
    return mappings.get(attack_type, {
        "technique_id": "T1068",
        "technique_name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "description": "Unknown attack technique requiring investigation"
    })

def get_mock_report_data(alert_id: str) -> ReportData:
    """Generate mock report data"""
    attack_types = [
        "Phishing Campaign", "Malware Infection", "Ransomware Attack",
        "DDoS Attack", "Data Exfiltration", "Privilege Escalation",
        "SQL Injection", "Cross-Site Scripting", "MITM Attack"
    ]
    hosts = [
        "web-server-01", "db-server-02", "app-server-03",
        "mail-server-04", "firewall-05", "endpoint-06"
    ]
    
    return ReportData(
        alert_id=alert_id,
        severity=random.choice(list(SeverityLevel)),
        attack_type=random.choice(attack_types),
        host=random.choice(hosts),
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
        status=random.choice(list(InvestigationStatus)),
        ioc=[
            f"192.168.{random.randint(1,255)}.{random.randint(1,255)}",
            f"malicious-domain-{random.randint(1,999)}.com",
            f"hash_{random.randint(100000,999999)}"
        ],
        summary="Suspicious activity detected requiring immediate investigation",
        source_ip=f"192.168.{random.randint(1,255)}.{random.randint(1,255)}",
        destination_ip=f"10.0.{random.randint(1,255)}.{random.randint(1,255)}",
        analyst="System"
    )