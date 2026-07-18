from collections import defaultdict
from typing import Any, Dict, Iterable, List, Literal, Optional, Set, Tuple


RiskLevel = Literal['Low', 'Medium', 'High', 'Critical']


def merge_tool_data(tool_responses: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """Merge data from multiple tool responses into a unified structure"""
    merged: Dict[str, Any] = {
        'alerts': [], 
        'events': [], 
        'ioc': [], 
        'intel': [], 
        'endpoints': [], 
        'tools': []
    }
    seen_items: Set[Tuple[str, str]] = set()

    for tool_response in tool_responses:
        tool_name = str(tool_response.get('tool_name', 'unknown'))
        merged['tools'].append(tool_name)
        payload = tool_response.get('data', {})

        if payload is None:
            continue

        # Handle different response types
        if 'alerts' in payload and isinstance(payload['alerts'], list):
            for alert in payload['alerts']:
                merged_item = _normalize_alert(alert, tool_name)
                _append_unique(merged['alerts'], merged_item, seen_items)

        if 'events' in payload and isinstance(payload['events'], list):
            for event in payload['events']:
                merged_item = _normalize_event(event, tool_name)
                _append_unique(merged['events'], merged_item, seen_items)

        if 'endpoint' in payload and isinstance(payload['endpoint'], dict):
            merged_item = _normalize_endpoint(payload['endpoint'], tool_name)
            _append_unique(merged['endpoints'], merged_item, seen_items)

        if 'result' in payload and isinstance(payload['result'], dict):
            merged_ioc = _extract_ioc(payload, tool_name)
            if merged_ioc:
                _append_unique(merged['ioc'], merged_ioc, seen_items)
            merged['intel'].append({'tool': tool_name, 'result': payload['result']})

        if 'indicator' in payload:
            merged_ioc = _extract_ioc(payload, tool_name)
            if merged_ioc:
                _append_unique(merged['ioc'], merged_ioc, seen_items)
            merged['intel'].append({'tool': tool_name, 'indicator': payload['indicator']})

        # Handle raw data
        if not any(key in payload for key in ['alerts', 'events', 'endpoint', 'result', 'indicator']):
            merged['intel'].append({'tool': tool_name, 'data': payload})

    merged['tools'] = sorted(set(merged['tools']))
    return merged


def _normalize_alert(alert: Dict[str, Any], tool_name: str) -> Dict[str, Any]:
    """Normalize alert data from different sources"""
    raw = alert.get("raw", {})
    
    return {
        "source": tool_name,
        "id": str(alert.get("id") or alert.get("alert_id") or "Unknown"),
        "title": alert.get("title", ""),
        "severity": str(alert.get("severity", "Low")).capitalize(),
        "summary": alert.get("description") or alert.get("summary", ""),
        # Enhanced fields for better reporting
        "hostname": alert.get("hostname") or raw.get("hostname") or raw.get("agent"),
        "agent": alert.get("agent") or raw.get("agent"),
        "username": alert.get("username") or raw.get("username"),
        "source_ip": alert.get("source_ip") or raw.get("src_ip") or raw.get("source_ip"),
        "destination_ip": alert.get("destination_ip") or raw.get("dst_ip") or raw.get("destination_ip"),
        "event": alert.get("event") or raw.get("event") or raw.get("title"),
        "mitre": alert.get("mitre") or raw.get("mitre") or raw.get("technique"),
        "status": alert.get("status") or raw.get("status", "Open"),
        "timestamp": alert.get("timestamp") or raw.get("timestamp"),
        "raw": alert,
    }


def _normalize_event(event: Dict[str, Any], tool_name: str) -> Dict[str, Any]:
    """Normalize event data from different sources"""
    return {
        'source': tool_name,
        'id': str(event.get('event_id') or event.get('id') or 'unknown'),
        'rule': str(event.get('rule') or '').strip(),
        'severity': str(event.get('severity', 'unknown')).capitalize(),
        'agent': str(event.get('agent') or event.get('host') or 'unknown'),
        'raw': event,
    }


def _normalize_endpoint(endpoint: Dict[str, Any], tool_name: str) -> Dict[str, Any]:
    """Normalize endpoint data from different sources"""
    return {
        'source': tool_name,
        'id': str(endpoint.get('id') or endpoint.get('agent_id') or endpoint.get('hostname') or 'unknown'),
        'hostname': str(endpoint.get('hostname') or endpoint.get('name') or 'unknown'),
        'ip': endpoint.get('ip') or endpoint.get('address'),
        'status': endpoint.get('status'),
        'os': endpoint.get('os'),
        'raw': endpoint,
    }


def _extract_ioc(payload: Dict[str, Any], tool_name: str) -> Optional[Dict[str, Any]]:
    """Extract IOCs from tool response"""
    # Try different fields where IOC might be stored
    indicator = (
        payload.get('indicator') 
        or payload.get('ip') 
        or payload.get('url') 
        or payload.get('hash')
    )
    
    if not indicator:
        data = payload.get('result', {})
        indicator = (
            data.get('id') 
            or data.get('indicator')
            or data.get('ip')
            or data.get('hash')
        )

    if not indicator:
        return None

    # Extract reputation if available
    reputation = (
        payload.get('reputation') 
        or payload.get('result', {}).get('reputation')
        or 'unknown'
    )
    
    # Extract additional VT-like fields
    result = payload.get('result', {})
    extra_info = {}
    if result:
        for field in ['country', 'detections', 'confidence', 'reputation']:
            if field in result:
                extra_info[field] = result[field]
    
    return {
        'source': tool_name,
        'indicator': str(indicator),
        'reputation': str(reputation).capitalize(),
        'extra_info': extra_info,
        'raw': payload,
    }


def _append_unique(collection: List[Dict[str, Any]], item: Dict[str, Any], seen_items: Set[Tuple[str, str]]) -> None:
    """Append item to collection if not already present"""
    key = (item.get('source', ''), str(item.get('id', item.get('indicator', ''))))
    if key not in seen_items:
        collection.append(item)
        seen_items.add(key)


def identify_relationships(merged: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Identify relationships between IOCs and alerts"""
    relationships: List[Dict[str, Any]] = []
    ip_to_alerts: Dict[str, List[str]] = defaultdict(list)

    # Build mapping of IPs to alert IDs
    for alert in merged.get("alerts", []):
        ip = (
            alert.get("source_ip")
            or alert.get("raw", {}).get("source_ip")
            or alert.get("raw", {}).get("src_ip")
            or alert.get("raw", {}).get("ip")
        )
        
        if ip:
            ip_to_alerts[str(ip)].append(alert["id"])

    # Find relationships between IOCs and alerts
    for ioc in merged.get("ioc", []):
        indicator = ioc.get("indicator")
        
        if indicator in ip_to_alerts:
            relationships.append({
                "ioc": indicator,
                "related_alerts": ip_to_alerts[indicator],
                "description": f"IOC {indicator} is related to {len(ip_to_alerts[indicator])} alert(s)."
            })

    # If no relationships found but we have both alerts and IOCs, create a default relationship
    if not relationships and merged.get("alerts") and merged.get("ioc"):
        # Find the most significant IOC (malicious reputation first)
        malicious_iocs = [i for i in merged["ioc"] if i.get('reputation', '').lower() == 'malicious']
        primary_ioc = malicious_iocs[0] if malicious_iocs else merged["ioc"][0]
        
        relationships.append({
            "ioc": primary_ioc["indicator"],
            "related_alerts": [a["id"] for a in merged["alerts"]],
            "description": f"Primary IOC is associated with {len(merged['alerts'])} alert(s)."
        })

    return relationships


def calculate_risk_score(merged: Dict[str, Any]) -> RiskLevel:
    """Calculate risk score based on merged data"""
    severity_map = {
        'Critical': 4, 
        'High': 3, 
        'Medium': 2, 
        'Low': 1, 
        'Unknown': 0
    }
    
    max_score = 0
    
    # Check alert severities
    for alert in merged.get('alerts', []):
        severity = alert.get('severity', 'Unknown').capitalize()
        max_score = max(max_score, severity_map.get(severity, 0))

    # Check for malicious IOCs
    if any(ioc.get('reputation', '').lower() == 'malicious' for ioc in merged.get('ioc', [])):
        max_score = max(max_score, severity_map['High'])

    # Consider volume of alerts/events
    if len(merged.get('alerts', [])) >= 3 or len(merged.get('events', [])) >= 5:
        max_score = max(max_score, severity_map['Critical'])

    # Map score to risk level
    risk_map = {
        4: 'Critical',
        3: 'High',
        2: 'Medium',
        1: 'Low',
        0: 'Low',
    }
    
    return risk_map.get(max_score, 'Low')


def build_summary(merged: Dict[str, Any], relationships: List[Dict[str, Any]]) -> str:
    """Build investigation summary"""
    alert_count = len(merged.get('alerts', []))
    ioc_count = len(merged.get('ioc', []))
    
    if relationships:
        primary = relationships[0]
        summary_parts = [
            f"{alert_count} alert(s) correlated with IOC {primary['ioc']}.",
            primary['description']
        ]
        
        # Add additional context if available
        if ioc_count > 1:
            summary_parts.append(f"Total of {ioc_count} IOCs identified.")
        
        return " ".join(summary_parts)

    if merged.get('alerts'):
        titles = [alert.get('title') for alert in merged['alerts'] if alert.get('title')]
        return titles[0] if titles else f'{alert_count} alert(s) correlated with threat intelligence data.'

    return 'Merged security data from multiple tools for unified investigation.'


def build_unified_investigation_result(tool_responses: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Build a unified investigation result from multiple tool responses.
    Enhanced to support all fields needed by the report generator.
    """
    # Merge all tool data
    merged = merge_tool_data(tool_responses)
    
    # Identify relationships
    relationships = identify_relationships(merged)
    
    # Calculate risk severity
    severity = calculate_risk_score(merged)
    
    # Select the alert that matches the correlated IOC
    selected_alert = None
    
    if relationships:
        primary_ioc = relationships[0]["ioc"]
        
        # Try to find an alert with source_ip matching the IOC
        for alert in merged["alerts"]:
            if alert.get("source_ip") == primary_ioc:
                selected_alert = alert
                break
        
        # If no match found with source_ip, try other fields
        if selected_alert is None:
            for alert in merged["alerts"]:
                raw = alert.get("raw", {})
                # Check if IOC appears anywhere in the alert
                if any(str(primary_ioc) in str(value) for value in alert.values()):
                    selected_alert = alert
                    break
    else:
        primary_ioc = (
            merged["ioc"][0]["indicator"]
            if merged["ioc"]
            else "Unknown IOC"
        )
    
    # Fallback to first alert if no match found
    if selected_alert is None and merged["alerts"]:
        selected_alert = merged["alerts"][0]
    
    # Calculate confidence score
    base_confidence = 70
    alert_boost = min(30, len(merged.get('alerts', [])) * 10)
    ioc_boost = min(20, len(merged.get('ioc', [])) * 5)
    confidence = f"{min(100, base_confidence + alert_boost + ioc_boost)}%"
    
    # Build summary
    summary = build_summary(merged, relationships)
    
    # Extract enhanced fields from selected alert
    source_ip = None
    destination_ip = None
    mitre_technique = None
    status = "Open"
    attack_type = "Unknown"
    
    if selected_alert:
        source_ip = selected_alert.get('source_ip')
        destination_ip = selected_alert.get('destination_ip')
        mitre_technique = selected_alert.get('mitre')
        status = selected_alert.get('status', 'Open')
        attack_type = selected_alert.get('event', 'Unknown')
        
        # Check raw for additional data
        raw = selected_alert.get('raw', {})
        if not source_ip:
            source_ip = raw.get('src_ip') or raw.get('source_ip')
        if not destination_ip:
            destination_ip = raw.get('dst_ip') or raw.get('destination_ip')
        if not mitre_technique:
            mitre_technique = raw.get('mitre') or raw.get('technique')
    
    # Extract VT results from intel
    vt_results = {}
    for intel_item in merged.get('intel', []):
        if intel_item.get('tool') == 'VirusTotal':
            result = intel_item.get('result', {})
            if result:
                vt_results = {
                    'reputation': result.get('reputation'),
                    'country': result.get('country'),
                    'detections': result.get('detections'),
                    'confidence': result.get('confidence')
                }
                break
    
    # Build the unified result with all required fields
    return {
        "alert_id": selected_alert["id"] if selected_alert else "Unknown",
        "severity": severity,
        "attack_type": attack_type,
        "affected_host": selected_alert.get("hostname", "Unknown") if selected_alert else "Unknown",
        "source_ip": source_ip or "N/A",
        "destination_ip": destination_ip or "N/A",
        "mitre_technique": mitre_technique or "N/A",
        "status": status,
        "ioc": primary_ioc if 'primary_ioc' in locals() else "Unknown IOC",
        "confidence": confidence,
        "summary": summary,
        "recommendations": _generate_recommendations(merged, severity, attack_type),
        "ioc_data": merged.get("ioc", []),
        "intel": merged.get("intel", []),
        "vt_results": vt_results,
        "details": {
            "tools": merged.get("tools", []),
            "relationships": relationships,
            "alerts": merged.get("alerts", []),
            "events": merged.get("events", [])
        }
    }


def _generate_recommendations(merged: Dict[str, Any], severity: str, attack_type: str) -> List[str]:
    """Generate intelligent recommendations based on investigation data"""
    recommendations = []
    
    # Base recommendations based on severity
    if severity in ['High', 'Critical']:
        recommendations.extend([
            "Immediately isolate affected systems",
            "Escalate to incident response team",
            "Preserve forensic evidence",
            "Block identified IOCs at network perimeter"
        ])
    elif severity == 'Medium':
        recommendations.extend([
            "Investigate affected endpoints",
            "Review access logs for suspicious activity",
            "Update security monitoring rules"
        ])
    else:
        recommendations.extend([
            "Monitor for additional alerts",
            "Document findings for future reference"
        ])
    
    # Attack type specific recommendations
    if "login" in attack_type.lower() or "brute" in attack_type.lower():
        recommendations.extend([
            "Reset compromised user passwords",
            "Enable Multi-Factor Authentication (MFA)",
            "Review failed login patterns"
        ])
    elif "malware" in attack_type.lower() or "ransom" in attack_type.lower():
        recommendations.extend([
            "Run full antivirus scan on affected hosts",
            "Check for persistence mechanisms",
            "Review backup integrity"
        ])
    elif "phishing" in attack_type.lower():
        recommendations.extend([
            "Notify affected users",
            "Review email filtering rules",
            "Check for additional phishing attempts"
        ])
    
    # IOC-based recommendations
    if merged.get("ioc"):
        recommendations.append("Block malicious IOCs at firewall and endpoint")
        recommendations.append("Search for additional instances of IOCs in environment")
    
    # Tool-specific recommendations
    if "VirusTotal" in merged.get("tools", []):
        recommendations.append("Monitor VirusTotal for reputation changes")
    
    if "Wazuh" in merged.get("tools", []):
        recommendations.append("Create custom Wazuh rules for detected patterns")
    
    # Remove duplicates while preserving order
    seen = set()
    unique_recommendations = []
    for rec in recommendations:
        if rec not in seen:
            seen.add(rec)
            unique_recommendations.append(rec)
    
    return unique_recommendations[:10]  # Limit to top 10 recommendations