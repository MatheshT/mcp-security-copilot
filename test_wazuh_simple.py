#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Simple test script for Wazuh integration
Tests basic connectivity and alert retrieval
"""
import requests
import json
import urllib3
import sys
import io

# Set UTF-8 encoding for Windows console
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# Disable SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Wazuh configuration
WAZUH_URL = "https://192.168.56.101:55000"
WAZUH_USERNAME = "wazuh-wui"
WAZUH_PASSWORD = "wazuh-wui"

def test_wazuh_authentication():
    """Test Wazuh authentication"""
    print("Test 1: Wazuh Authentication")
    try:
        auth_url = f"{WAZUH_URL}/security/user/authenticate?raw=true"
        response = requests.get(
            auth_url,
            auth=(WAZUH_USERNAME, WAZUH_PASSWORD),
            verify=False,
            timeout=10
        )
        
        if response.status_code == 200:
            token = response.text.strip()
            print(f"[SUCCESS] Authentication SUCCESS")
            print(f"  Token obtained: {token[:20]}...")
            return token
        else:
            print(f"[FAILED] Authentication FAILED")
            print(f"  Status code: {response.status_code}")
            return None
    except Exception as e:
        print(f"[ERROR] Authentication ERROR: {e}")
        return None

def get_wazuh_alerts(token, severity="all", limit=50):
    """Get Wazuh alerts with optional severity filtering"""
    headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
    
    alert_endpoints = [
        'api/v4/alerts',
        'manager/logs/alerts',
        'alerts'
    ]
    
    for endpoint in alert_endpoints:
        try:
            url = f"{WAZUH_URL}/{endpoint}"
            params = {"limit": limit}
            response = requests.get(url, headers=headers, params=params, verify=False, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, dict) and 'data' in data:
                    if 'affected_items' in data['data']:
                        alerts = data['data']['affected_items']
                        return alerts
                    elif 'items' in data['data']:
                        alerts = data['data']['items']
                        return alerts
        except Exception as e:
            print(f"  Error with endpoint {endpoint}: {e}")
            continue
    
    return []

def filter_alerts_by_severity(alerts, severity):
    """Filter alerts by severity level"""
    severity_mapping = {
        'critical': [12, 13, 14, 15],
        'high': [10, 11],
        'medium': [7, 8, 9],
        'low': [1, 2, 3, 4, 5, 6]
    }
    
    if severity not in severity_mapping:
        return alerts
    
    severity_levels = severity_mapping[severity]
    filtered_alerts = []
    
    for alert in alerts:
        alert_severity = None
        if 'rule' in alert and 'level' in alert['rule']:
            alert_severity = alert['rule']['level']
        elif 'level' in alert:
            alert_severity = alert['level']
        
        if alert_severity in severity_levels:
            filtered_alerts.append(alert)
    
    return filtered_alerts

def main():
    print("="*60)
    print("Wazuh Integration Test")
    print("="*60)
    
    # Test authentication
    token = test_wazuh_authentication()
    if not token:
        print("\nCannot proceed without authentication")
        return
    
    # Test collecting all alerts
    print("\nTest 2: Collect All Alerts")
    all_alerts = get_wazuh_alerts(token, "all", 100)
    print(f"[SUCCESS] Total alerts collected: {len(all_alerts)}")
    
    if all_alerts:
        print(f"  Sample alert: {json.dumps(all_alerts[0], indent=2)[:200]}...")
    
    # Test severity filtering
    print("\nTest 3: Severity Filtering")
    for severity in ["critical", "high", "medium", "low"]:
        filtered = filter_alerts_by_severity(all_alerts, severity)
        print(f"  {severity.upper()}: {len(filtered)} alerts")
    
    # Test getting alerts by severity groups
    print("\nTest 4: Alerts by Severity Groups")
    severity_groups = {
        "critical": filter_alerts_by_severity(all_alerts, "critical")[:20],
        "high": filter_alerts_by_severity(all_alerts, "high")[:20],
        "medium": filter_alerts_by_severity(all_alerts, "medium")[:20],
        "low": filter_alerts_by_severity(all_alerts, "low")[:20]
    }
    
    for severity, alerts in severity_groups.items():
        print(f"  {severity.upper()}: {len(alerts)} alerts")
        if alerts:
            print(f"    Sample: {alerts[0].get('rule', {}).get('description', 'No description')}")
    
    print("\n" + "="*60)
    print("Wazuh Integration Test Complete!")
    print("="*60)

if __name__ == "__main__":
    main()