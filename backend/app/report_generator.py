from datetime import datetime
from html import escape
from typing import Any, Dict, List, Optional


def _format_timestamp(timestamp: Optional[datetime] = None) -> str:
    return (timestamp or datetime.utcnow()).strftime("%Y-%m-%d %H:%M:%S UTC")


def _ensure_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def _extract_iocs(report: Dict[str, Any]) -> List[str]:
    """Extract IOCs from ioc_data only"""
    iocs = []

    for item in report.get("ioc_data", []):
        if not isinstance(item, dict):
            continue

        indicator = (
            item.get("indicator")
            or item.get("ip")
            or item.get("id")
        )

        if indicator:
            iocs.append(str(indicator))

    return list(dict.fromkeys(iocs))


def _extract_threat_intelligence(report: Dict[str, Any]) -> List[str]:
    intel = []

    # Check VT results
    vt_results = report.get("vt_results", {})
    if vt_results:
        if "reputation" in vt_results:
            intel.append(f"Reputation: {vt_results['reputation']}")
        if "country" in vt_results:
            intel.append(f"Country: {vt_results['country']}")
        if "detections" in vt_results:
            intel.append(f"Detections: {vt_results['detections']}")
        if "confidence" in vt_results:
            intel.append(f"Confidence: {vt_results['confidence']}%")

    # Check existing intel data
    for item in report.get("intel", []):
        if not isinstance(item, dict):
            continue

        if "result" in item:
            value = item["result"]
            if isinstance(value, dict):
                value = ", ".join(f"{k}: {v}" for k, v in value.items())
            intel.append(str(value))
        elif "indicator" in item:
            intel.append(str(item["indicator"]))
        elif "data" in item:
            intel.append(str(item["data"]))

    return list(dict.fromkeys(intel))


def _extract_host(report: Dict[str, Any]) -> str:
    """Extract affected host with priority: hostname > agent"""
    
    alerts = report.get("details", {}).get("alerts", [])
    if alerts:
        alert = alerts[0]
        raw = alert.get("raw", {})
        
        # Priority: hostname first, then agent
        return (
            alert.get("hostname")
            or raw.get("hostname")
            or alert.get("agent")
            or raw.get("agent")
            or raw.get("computer")
            or raw.get("host")
            or "Unknown Host"
        )

    endpoints = report.get("endpoints", [])
    if endpoints:
        return endpoints[0].get("hostname") or endpoints[0].get("id")

    return "Unknown Host"


def _extract_source_ip(report: Dict[str, Any]) -> str:
    alerts = report.get("details", {}).get("alerts", [])

    for alert in alerts:
        # Check top-level field first
        if alert.get("source_ip"):
            return str(alert["source_ip"])

        raw = alert.get("raw", {})
        for field in ["src_ip", "source_ip", "ip", "src"]:
            if raw.get(field):
                return str(raw[field])

    return "N/A"


def _extract_destination_ip(report: Dict[str, Any]) -> str:
    alerts = report.get("details", {}).get("alerts", [])

    for alert in alerts:
        # Check top-level field first
        if alert.get("destination_ip"):
            return str(alert["destination_ip"])

        raw = alert.get("raw", {})
        for field in ["dst_ip", "destination_ip", "dest"]:
            if raw.get(field):
                return str(raw[field])

    return "N/A"


def _extract_mitre_technique(report: Dict[str, Any]) -> str:
    alerts = report.get("details", {}).get("alerts", [])

    for alert in alerts:
        # Check top-level field first
        if alert.get("mitre"):
            return str(alert["mitre"])

        raw = alert.get("raw", {})

        if raw.get("mitre"):
            return str(raw["mitre"])

        if raw.get("technique"):
            return str(raw["technique"])

    return "N/A"


def _extract_status(report: Dict[str, Any]) -> str:
    """Extract alert status"""
    alerts = report.get("details", {}).get("alerts", [])
    for alert in alerts:
        if "status" in alert:
            return str(alert["status"])
        raw = alert.get("raw", {})
        if "status" in raw:
            return str(raw["status"])
    return "Open"


def _detect_attack(report: Dict[str, Any]) -> str:
    """Detect attack type with priority on alert events"""
    
    # 1. Check alerts first (best source)
    alerts = report.get("details", {}).get("alerts", [])
    if alerts:
        alert = alerts[0]
        raw = alert.get("raw", {})
        
        # Check multiple fields for event description
        event = (
            alert.get("event")
            or alert.get("title")
            or alert.get("description")
            or raw.get("event")
            or raw.get("title")
            or raw.get("description")
            or raw.get("rule")
            or ""
        )
        
        if event and event != "Unknown":
            # Clean up the event description
            event = str(event).strip()
            if len(event) > 100:
                event = event[:100] + "..."
            return event

    # 2. Fallback to summary with more patterns
    summary = str(report.get("summary", "")).lower()
    
    # Define patterns with priority
    patterns = {
        "Multiple Failed Login Attempts": ["multiple failed login", "failed login", "brute force"],
        "Brute Force SSH Attack": ["ssh brute", "ssh failed", "ssh login failure"],
        "Malware Infection": ["malware", "virus", "trojan", "ransomware"],
        "Ransomware": ["ransom", "encrypt", "decrypt", "lock"],
        "Phishing": ["phish", "phish"],
        "Data Exfiltration": ["exfil", "data leak", "data transfer"],
        "Privilege Escalation": ["privilege", "escalation", "elevated"],
        "Lateral Movement": ["lateral", "movement", "psexec", "wmi"],
        "Command Injection": ["injection", "command", "execution"],
        "DDoS": ["ddos", "dos attack", "flood"]
    }
    
    for attack_type, keywords in patterns.items():
        if any(keyword in summary for keyword in keywords):
            return attack_type

    return "Unknown"


def generate_report_json(
    report_payload: Dict[str, Any],
    alert_id=None,
    timestamp=None,
    attack_type=None,
    recommendations=None,
) -> Dict[str, Any]:
    """Generate a structured report JSON"""
    
    report = {
        "alert_id": alert_id or report_payload.get("alert_id") or "Unknown",
        "timestamp": _format_timestamp(timestamp),
        "severity": report_payload.get("severity", "Unknown"),
        "attack_type": attack_type or _detect_attack(report_payload),
        "affected_host": _extract_host(report_payload),
        "source_ip": _extract_source_ip(report_payload),
        "destination_ip": _extract_destination_ip(report_payload),
        "mitre_technique": _extract_mitre_technique(report_payload),
        "status": _extract_status(report_payload),
        "indicators_of_compromise": _extract_iocs(report_payload),
        "threat_intelligence": _extract_threat_intelligence(report_payload),
        "investigation_summary": report_payload.get(
            "summary", "No investigation summary available."
        ),
        "recommendations": _ensure_list(
            recommendations or report_payload.get("recommendations")
        ),
    }
    
    return report


def generate_report_html(report_json: Dict[str, Any]) -> str:
    """Generate HTML report from JSON data"""
    
    html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Investigation Report</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: #f5f6fa;
            padding: 30px;
            margin: 0;
        }}
        .container {{
            max-width: 1000px;
            margin: 0 auto;
        }}
        .header {{
            background: linear-gradient(135deg, #1a1a2e, #16213e);
            color: white;
            padding: 20px 30px;
            border-radius: 10px 10px 0 0;
        }}
        .header h1 {{
            margin: 0;
            font-size: 1.8rem;
        }}
        .header p {{
            margin: 5px 0 0;
            opacity: 0.8;
        }}
        .card {{
            background: white;
            padding: 20px 30px;
            border-bottom: 1px solid #e2e8f0;
        }}
        .card:last-child {{
            border-radius: 0 0 10px 10px;
            border-bottom: none;
        }}
        .card h2 {{
            color: #2c3e50;
            font-size: 1.2rem;
            margin: 0 0 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid #e2e8f0;
        }}
        .grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
        }}
        .field {{
            display: flex;
            flex-direction: column;
        }}
        .field .label {{
            font-size: 0.8rem;
            text-transform: uppercase;
            color: #64748b;
            font-weight: 600;
            letter-spacing: 0.05em;
        }}
        .field .value {{
            font-size: 1rem;
            padding: 5px 0;
            font-weight: 500;
            color: #0f172a;
        }}
        .severity-critical {{
            color: #dc2626;
            font-weight: 700;
        }}
        .severity-high {{
            color: #f59e0b;
            font-weight: 700;
        }}
        .severity-medium {{
            color: #fbbf24;
            font-weight: 700;
        }}
        .severity-low {{
            color: #10b981;
            font-weight: 700;
        }}
        .ioc-container {{
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
        }}
        .ioc-tag {{
            background: #e2e8f0;
            padding: 4px 12px;
            border-radius: 16px;
            font-family: monospace;
            font-size: 0.9rem;
            color: #0f172a;
        }}
        .threat-list, .recommendations-list {{
            padding-left: 20px;
            margin: 0;
        }}
        .threat-list li, .recommendations-list li {{
            padding: 4px 0;
            line-height: 1.5;
        }}
        .summary-box {{
            background: #f8fafc;
            padding: 15px;
            border-left: 4px solid #3b82f6;
            border-radius: 4px;
            margin: 0;
            line-height: 1.6;
        }}
        .status-badge {{
            display: inline-block;
            padding: 2px 12px;
            border-radius: 12px;
            font-size: 0.8rem;
            font-weight: 600;
        }}
        .status-open {{
            background: #3b82f6;
            color: white;
        }}
        .status-closed {{
            background: #10b981;
            color: white;
        }}
        .status-in-progress {{
            background: #f59e0b;
            color: #1e1e2e;
        }}
        @media (max-width: 768px) {{
            .grid {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>🚨 AI Security Investigation Report</h1>
        <p>Generated on {escape(str(report_json["timestamp"]))}</p>
    </div>

    <div class="card">
        <h2>📋 Incident Details</h2>
        <div class="grid">
            <div class="field">
                <span class="label">Alert ID</span>
                <span class="value">{escape(str(report_json["alert_id"]))}</span>
            </div>
            <div class="field">
                <span class="label">Severity</span>
                <span class="value severity-{escape(str(report_json["severity"]).lower())}">
                    {escape(str(report_json["severity"]))}
                </span>
            </div>
            <div class="field">
                <span class="label">Attack Type</span>
                <span class="value">{escape(str(report_json["attack_type"]))}</span>
            </div>
            <div class="field">
                <span class="label">Status</span>
                <span class="value">
                    <span class="status-badge status-{escape(str(report_json["status"]).lower())}">
                        {escape(str(report_json["status"]))}
                    </span>
                </span>
            </div>
            <div class="field">
                <span class="label">Affected Host</span>
                <span class="value">{escape(str(report_json["affected_host"]))}</span>
            </div>
            <div class="field">
                <span class="label">Source IP</span>
                <span class="value">{escape(str(report_json["source_ip"]))}</span>
            </div>
            <div class="field">
                <span class="label">Destination IP</span>
                <span class="value">{escape(str(report_json["destination_ip"]))}</span>
            </div>
            <div class="field">
                <span class="label">MITRE Technique</span>
                <span class="value">{escape(str(report_json["mitre_technique"]))}</span>
            </div>
        </div>
    </div>

    <div class="card">
        <h2>🌐 Indicators of Compromise</h2>
        <div class="ioc-container">
"""

    if report_json["indicators_of_compromise"]:
        for ioc in report_json["indicators_of_compromise"]:
            html += f'<span class="ioc-tag">{escape(str(ioc))}</span>'
    else:
        html += '<p style="color:#64748b;font-style:italic;">No IOCs identified</p>'

    html += f"""
        </div>
    </div>

    <div class="card">
        <h2>🛡 Threat Intelligence</h2>
        <ul class="threat-list">
"""

    if report_json["threat_intelligence"]:
        for intel in report_json["threat_intelligence"]:
            html += f'<li>{escape(str(intel))}</li>'
    else:
        html += '<li style="color:#64748b;font-style:italic;">No threat intelligence available</li>'

    html += f"""
        </ul>
    </div>

    <div class="card">
        <h2>📊 Investigation Summary</h2>
        <p class="summary-box">{escape(str(report_json["investigation_summary"]))}</p>
    </div>

    <div class="card">
        <h2>✅ Recommendations</h2>
        <ul class="recommendations-list">
"""

    if report_json["recommendations"]:
        for rec in report_json["recommendations"]:
            html += f'<li>• {escape(str(rec))}</li>'
    else:
        html += '<li style="color:#64748b;font-style:italic;">No recommendations available</li>'

    html += """
        </ul>
    </div>
</div>
</body>
</html>
"""

    return html