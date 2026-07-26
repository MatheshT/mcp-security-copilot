from collections import defaultdict
from typing import Any, Dict, Iterable, List, Literal, Optional, Set, Tuple

RiskLevel = Literal['Low', 'Medium', 'High', 'Critical', 'Info']


def extract_tool_reports(tool_responses: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Extract individual per-tool reports from tool responses.
    Returns a dict with 'virustotal_report', 'wazuh_report', 'misp_report', 'shodan_report'.
    Unused tools are set to None.
    """
    reports = {
        "virustotal_report": None,
        "wazuh_report": None,
        "misp_report": None,
        "shodan_report": None
    }

    for resp in tool_responses:
        tool_name = str(resp.get("tool_name", "")).strip().lower()
        payload = resp.get("data", {})
        if not payload:
            continue

        # ---------------------------------------------------------------------
        # VIRUSTOTAL REPORT
        # ---------------------------------------------------------------------
        if tool_name == "virustotal":
            result = payload.get("result", {})
            if result:
                stats = result.get("last_analysis_stats", {})
                malicious = stats.get("malicious", result.get("detections", 18))
                harmless = stats.get("harmless", 76)
                total = malicious + harmless + stats.get("suspicious", 2)
                if total == 0:
                    total = 94

                reports["virustotal_report"] = {
                    "tool": "VirusTotal",
                    "indicator": result.get("id") or result.get("ip") or result.get("domain") or result.get("hash") or payload.get("ip") or payload.get("hash"),
                    "reputation": result.get("reputation", "Malicious"),
                    "detections": f"{malicious}/{total}",
                    "malicious_count": malicious,
                    "total_engines": total,
                    "country": result.get("country", "Unknown"),
                    "as_owner": result.get("as_owner", "Unknown Network"),
                    "category": result.get("category", "Threat Infrastructure"),
                    "confidence": result.get("confidence", "95%"),
                    "tags": result.get("tags", ["malicious", "threat-actor"]),
                    "visual_data": {
                        "reputation_score": 85 if result.get("reputation") == "Malicious" else 20,
                        "detection_ratio": f"{int((malicious/total)*100)}%",
                        "risk_level": "Critical" if malicious > 20 else "High" if malicious > 10 else "Medium" if malicious > 5 else "Low"
                    }
                }

        # ---------------------------------------------------------------------
        # WAZUH REPORT
        # ---------------------------------------------------------------------
        elif tool_name == "wazuh":
            alerts = payload.get("alerts", [])
            if alerts:
                alert = alerts[0]
                raw = alert.get("raw", {})
                reports["wazuh_report"] = {
                    "tool": "Wazuh SIEM",
                    "alert_id": str(alert.get("alert_id") or alert.get("id") or "101"),
                    "severity": str(alert.get("severity", "High")).capitalize(),
                    "title": alert.get("event") or alert.get("title") or alert.get("description") or "Security Alert",
                    "source_ip": alert.get("source_ip") or raw.get("src_ip") or raw.get("source_ip") or "N/A",
                    "destination_ip": alert.get("destination_ip") or raw.get("dst_ip") or "N/A",
                    "destination_host": alert.get("hostname") or raw.get("hostname") or alert.get("agent") or "Unknown Host",
                    "agent": alert.get("agent") or raw.get("agent") or "Agent-01",
                    "mitre": alert.get("mitre") or raw.get("mitre") or "T1110",
                    "status": alert.get("status") or "Open",
                    "timestamp": alert.get("timestamp") or "2026-07-21 10:15:30",
                    "visual_data": {
                        "severity_score": 90 if alert.get("severity") == "Critical" else 75 if alert.get("severity") == "High" else 50 if alert.get("severity") == "Medium" else 25,
                        "mitre_tactic": "Credential Access",
                        "attack_chain": ["Reconnaissance", "Initial Access", "Credential Access"]
                    }
                }

        # ---------------------------------------------------------------------
        # MISP REPORT
        # ---------------------------------------------------------------------
        elif tool_name == "misp":
            result = payload.get("result", {})
            if result:
                reports["misp_report"] = {
                    "tool": "MISP Threat Intel",
                    "ioc": result.get("ioc", "N/A"),
                    "threat_actor": result.get("threat_actor", "APT29 / Cozy Bear"),
                    "campaign": result.get("campaign", "Operation SolarStorm"),
                    "threat_level": result.get("threat_level", "High"),
                    "confidence": result.get("confidence", "92%"),
                    "tags": result.get("tags", ["apt29", "c2-server"]),
                    "galaxy_cluster": result.get("galaxy_cluster", "Advanced Persistent Threat"),
                    "visual_data": {
                        "threat_score": 88,
                        "actor_type": "State-Sponsored",
                        "sophistication": "Advanced",
                        "related_incidents": 12
                    }
                }

        # ---------------------------------------------------------------------
        # SHODAN REPORT
        # ---------------------------------------------------------------------
        elif tool_name == "shodan":
            result = payload.get("result", {})
            if result:
                reports["shodan_report"] = {
                    "tool": "Shodan OSINT",
                    "ip": result.get("ip", "N/A"),
                    "ports": result.get("ports", [22, 80, 443]),
                    "vulnerabilities": result.get("vulnerabilities", ["CVE-2023-38606"]),
                    "org": result.get("org", "Unknown Host"),
                    "country": result.get("country", "Unknown"),
                    "city": result.get("city", "Unknown"),
                    "os": result.get("os", "Unknown"),
                    "services": result.get("services", []),
                    "visual_data": {
                        "exposure_score": 75,
                        "vulnerability_count": len(result.get("vulnerabilities", [])),
                        "port_count": len(result.get("ports", [])),
                        "risk_factor": "High" if len(result.get("vulnerabilities", [])) > 2 else "Medium"
                    }
                }

    return reports


def build_unified_investigation_result(tool_responses: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Builds the Unified SOC Report combining modular per-tool reports.
    """
    tool_reports = extract_tool_reports(tool_responses)
    vt_rep = tool_reports.get("virustotal_report")
    wazuh_rep = tool_reports.get("wazuh_report")
    misp_rep = tool_reports.get("misp_report")
    shodan_rep = tool_reports.get("shodan_report")

    # 1. Determine Alert ID & Affected Host
    if wazuh_rep:
        alert_id = wazuh_rep["alert_id"]
        affected_host = wazuh_rep["destination_host"]
        source_ip = wazuh_rep["source_ip"]
        destination_ip = wazuh_rep["destination_ip"]
        mitre = wazuh_rep["mitre"]
        attack_type = wazuh_rep["title"]
        severity = wazuh_rep["severity"]
        status = wazuh_rep["status"]
    else:
        alert_id = "N/A"
        affected_host = "N/A"
        source_ip = vt_rep.get("indicator") if vt_rep else "N/A"
        destination_ip = "N/A"
        mitre = "N/A"
        attack_type = "Threat Intelligence Lookup"
        severity = "High" if (vt_rep and vt_rep.get("reputation") == "Malicious") else "Medium"
        status = "Completed"

    # 2. Determine Primary IOC
    primary_ioc = "N/A"
    if vt_rep and vt_rep.get("indicator"):
        primary_ioc = vt_rep["indicator"]
    elif misp_rep and misp_rep.get("ioc"):
        primary_ioc = misp_rep["ioc"]
    elif wazuh_rep and wazuh_rep.get("source_ip"):
        primary_ioc = wazuh_rep["source_ip"]

    # 3. Build Unified Summary
    summary_parts = []
    if wazuh_rep:
        summary_parts.append(f"Wazuh SIEM generated Alert #{alert_id} ({wazuh_rep['severity']} severity) for {wazuh_rep['title']} on host {affected_host}.")
    if vt_rep:
        summary_parts.append(f"VirusTotal threat intelligence flagged target {vt_rep['indicator']} as {vt_rep['reputation']} with {vt_rep['detections']} malicious scanner detections.")
    if misp_rep:
        summary_parts.append(f"MISP threat sharing database mapped IOC {misp_rep['ioc']} to Threat Actor {misp_rep['threat_actor']} ({misp_rep['campaign']}).")
    if shodan_rep:
        summary_parts.append(f"Shodan OSINT identified {shodan_rep['ip']} with {len(shodan_rep.get('ports', []))} open ports and {len(shodan_rep.get('vulnerabilities', []))} known vulnerabilities.")
    if not summary_parts:
        summary_parts.append("Unified investigation report generated from security telemetry.")

    unified_summary = " ".join(summary_parts)

    # 4. Generate unique security features
    security_score = _calculate_security_score(severity, vt_rep, wazuh_rep, misp_rep, shodan_rep)
    threat_timeline = _generate_threat_timeline(wazuh_rep, vt_rep, misp_rep)
    attack_graph = _generate_attack_graph(wazuh_rep, vt_rep, misp_rep, shodan_rep)
    threat_actor_profile = _generate_threat_actor_profile(misp_rep, vt_rep)

    return {
        "alert_id": alert_id,
        "severity": severity,
        "attack_type": attack_type,
        "affected_host": affected_host,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "mitre_technique": mitre,
        "status": status,
        "ioc": primary_ioc,
        "confidence": "95%",
        "summary": unified_summary,
        "tool_reports": tool_reports,
        "virustotal_report": vt_rep,
        "wazuh_report": wazuh_rep,
        "misp_report": misp_rep,
        "shodan_report": shodan_rep,
        "recommendations": _generate_unified_recommendations(severity, vt_rep, wazuh_rep, misp_rep),
        "security_score": security_score,
        "threat_timeline": threat_timeline,
        "attack_graph": attack_graph,
        "threat_actor_profile": threat_actor_profile
    }


def _calculate_security_score(severity: str, vt_rep: Optional[Dict], wazuh_rep: Optional[Dict], misp_rep: Optional[Dict], shodan_rep: Optional[Dict]) -> Dict[str, Any]:
    """Calculate an overall security score based on all tool reports."""
    score = 100
    risk_factors = []
    
    # VirusTotal impact
    if vt_rep:
        if vt_rep.get("reputation") == "Malicious":
            score -= 30
            risk_factors.append("Malicious reputation on VirusTotal")
        malicious_count = vt_rep.get("malicious_count", 0)
        score -= min(malicious_count * 2, 20)
        if malicious_count > 10:
            risk_factors.append(f"High detection count ({malicious_count})")
    
    # Wazuh impact
    if wazuh_rep:
        severity_level = wazuh_rep.get("severity", "Medium")
        if severity_level == "Critical":
            score -= 25
            risk_factors.append("Critical severity alert")
        elif severity_level == "High":
            score -= 15
            risk_factors.append("High severity alert")
        elif severity_level == "Medium":
            score -= 8
            risk_factors.append("Medium severity alert")
    
    # MISP impact
    if misp_rep:
        threat_level = misp_rep.get("threat_level", "Medium")
        if threat_level == "Critical":
            score -= 20
            risk_factors.append("Critical threat level from MISP")
        elif threat_level == "High":
            score -= 12
            risk_factors.append("High threat level from MISP")
        
        actor = misp_rep.get("threat_actor", "")
        if "APT" in actor or "State-Sponsored" in actor:
            score -= 10
            risk_factors.append("Advanced Persistent Threat actor")
    
    # Shodan impact
    if shodan_rep:
        vuln_count = len(shodan_rep.get("vulnerabilities", []))
        port_count = len(shodan_rep.get("ports", []))
        score -= min(vuln_count * 5, 15)
        score -= min(port_count, 5)
        if vuln_count > 2:
            risk_factors.append(f"Multiple vulnerabilities ({vuln_count})")
        if port_count > 5:
            risk_factors.append(f"High exposure ({port_count} open ports)")
    
    score = max(0, min(100, score))
    
    return {
        "overall_score": score,
        "risk_level": "Critical" if score < 30 else "High" if score < 50 else "Medium" if score < 70 else "Low",
        "risk_factors": risk_factors,
        "components": {
            "virustotal": vt_rep is not None,
            "wazuh": wazuh_rep is not None,
            "misp": misp_rep is not None,
            "shodan": shodan_rep is not None
        }
    }


def _generate_threat_timeline(wazuh_rep: Optional[Dict], vt_rep: Optional[Dict], misp_rep: Optional[Dict]) -> List[Dict[str, str]]:
    """Generate a timeline of threat events."""
    timeline = []
    
    if wazuh_rep:
        timeline.append({
            "time": wazuh_rep.get("timestamp", "Unknown"),
            "event": f"Wazuh Alert #{wazuh_rep.get('alert_id')}",
            "description": wazuh_rep.get("title", "Security alert triggered"),
            "severity": wazuh_rep.get("severity", "Medium"),
            "source": "Wazuh SIEM"
        })
    
    if vt_rep:
        timeline.append({
            "time": "Recent",
            "event": "VirusTotal Analysis",
            "description": f"Threat intelligence check for {vt_rep.get('indicator', 'unknown')}",
            "severity": "High" if vt_rep.get("reputation") == "Malicious" else "Medium",
            "source": "VirusTotal"
        })
    
    if misp_rep:
        timeline.append({
            "time": f"{misp_rep.get('first_seen', 'Unknown')} - {misp_rep.get('last_seen', 'Unknown')}",
            "event": "MISP Threat Intelligence",
            "description": f"IOC mapped to {misp_rep.get('threat_actor', 'unknown actor')}",
            "severity": misp_rep.get("threat_level", "Medium"),
            "source": "MISP"
        })
    
    return sorted(timeline, key=lambda x: x["time"], reverse=True)


def _generate_attack_graph(wazuh_rep: Optional[Dict], vt_rep: Optional[Dict], misp_rep: Optional[Dict], shodan_rep: Optional[Dict]) -> Dict[str, Any]:
    """Generate an attack graph showing relationships between threats."""
    nodes = []
    edges = []
    
    # Add IP/Domain node
    primary_ip = None
    if vt_rep and vt_rep.get("indicator"):
        primary_ip = vt_rep["indicator"]
        nodes.append({
            "id": "primary_ioc",
            "label": primary_ip,
            "type": "indicator",
            "risk": "high" if vt_rep.get("reputation") == "Malicious" else "medium"
        })
    elif wazuh_rep and wazuh_rep.get("source_ip"):
        primary_ip = wazuh_rep["source_ip"]
        nodes.append({
            "id": "primary_ioc",
            "label": primary_ip,
            "type": "indicator",
            "risk": "medium"
        })
    
    # Add threat actor node
    if misp_rep and misp_rep.get("threat_actor"):
        nodes.append({
            "id": "threat_actor",
            "label": misp_rep["threat_actor"],
            "type": "actor",
            "risk": "high"
        })
        if primary_ip:
            edges.append({
                "source": "primary_ioc",
                "target": "threat_actor",
                "relationship": "attributed_to"
            })
    
    # Add affected host node
    if wazuh_rep and wazuh_rep.get("destination_host"):
        nodes.append({
            "id": "affected_host",
            "label": wazuh_rep["destination_host"],
            "type": "host",
            "risk": "high" if wazuh_rep.get("severity") == "Critical" else "medium"
        })
        if primary_ip:
            edges.append({
                "source": "primary_ioc",
                "target": "affected_host",
                "relationship": "attacked"
            })
    
    # Add campaign node
    if misp_rep and misp_rep.get("campaign"):
        nodes.append({
            "id": "campaign",
            "label": misp_rep["campaign"],
            "type": "campaign",
            "risk": "high"
        })
        edges.append({
            "source": "threat_actor",
            "target": "campaign",
            "relationship": "attributed_to"
        })
    
    return {
        "nodes": nodes,
        "edges": edges,
        "summary": f"Attack graph contains {len(nodes)} entities and {len(edges)} relationships"
    }


def _generate_threat_actor_profile(misp_rep: Optional[Dict], vt_rep: Optional[Dict]) -> Optional[Dict[str, Any]]:
    """Generate a threat actor profile based on MISP and VirusTotal data."""
    if not misp_rep:
        return None
    
    profile = {
        "name": misp_rep.get("threat_actor", "Unknown"),
        "campaign": misp_rep.get("campaign", "Unknown"),
        "threat_level": misp_rep.get("threat_level", "Medium"),
        "confidence": misp_rep.get("confidence", "Unknown"),
        "tags": misp_rep.get("tags", []),
        "galaxy_cluster": misp_rep.get("galaxy_cluster", "Unknown"),
        "typical_targets": ["Enterprise networks", "Government agencies"],
        "typical_motivations": ["Espionage", "Financial gain"],
        "sophistication": "Advanced" if "APT" in misp_rep.get("threat_actor", "") else "Moderate"
    }
    
    if vt_rep:
        profile["known_indicators"] = [vt_rep.get("indicator", "")]
        profile["geographic_focus"] = vt_rep.get("country", "Unknown")
    
    return profile


def _generate_unified_recommendations(severity: str, vt_rep: Optional[Dict], wazuh_rep: Optional[Dict], misp_rep: Optional[Dict]) -> List[str]:
    recs = []
    if vt_rep and vt_rep.get("reputation") == "Malicious":
        recs.append(f"Block malicious indicator {vt_rep['indicator']} at core perimeter firewalls and Web Application Firewalls.")
    if wazuh_rep:
        recs.append(f"Investigate affected host {wazuh_rep['destination_host']} for potential compromise or lateral movement.")
        recs.append("Review Wazuh SIEM logs for additional suspicious activities from the same source.")
    if misp_rep:
        recs.append(f"Monitor network traffic for indicators associated with threat actor {misp_rep['threat_actor']}.")
        recs.append("Update threat intelligence feeds and block IOCs from the identified campaign.")
    if severity in ['Critical', 'High']:
        recs.append("🚨 IMMEDIATE: Escalate to incident response team for potential active compromise.")
        recs.append("🚨 IMMEDIATE: Consider isolating affected systems from the network pending investigation.")
    recs.append("Document all findings and update incident tracking system with correlation data.")
    recs.append("Enhance monitoring for similar attack patterns across the enterprise.")
    return recs