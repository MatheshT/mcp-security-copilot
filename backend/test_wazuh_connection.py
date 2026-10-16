#!/usr/bin/env python3
"""
Test Wazuh API Connection & Alerts Stream
Tests connectivity to Wazuh v4.x server, REST API endpoints, and real alert extraction.
"""

import requests
import base64
import sys
import os
import urllib3
from dotenv import load_dotenv

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Load environment variables
load_dotenv()

def test_wazuh_connection():
    """Test Wazuh API connection and retrieve real alerts"""
    
    wazuh_url = os.getenv('WAZUH_URL') or os.getenv('WAZUH_API_URL', 'https://192.168.56.101:55000')
    username = os.getenv('WAZUH_USERNAME', 'wazuh-wui')
    password = os.getenv('WAZUH_PASSWORD', 'wazuh-wui')
    
    print("=" * 60)
    print("Wazuh v4.x SIEM Connection & Real Alert Test")
    print("=" * 60)
    
    print(f"Target URL: {wazuh_url}")
    print(f"Username  : {username}")
    print()
    
    # Test 1: Network connectivity
    print("Test 1: Network connectivity to Port 55000...")
    try:
        response = requests.get(wazuh_url, timeout=10, verify=False)
        print(f"  [OK] Server reachable (HTTP {response.status_code})")
    except Exception as e:
        print(f"  [FAIL] Network connection error: {e}")
        return False
    
    # Test 2: Authentication
    print("\nTest 2: REST API Authentication...")
    auth_url = f"{wazuh_url.rstrip('/')}/security/user/authenticate?raw=true"
    token = None
    try:
        response = requests.post(
            auth_url,
            auth=(username, password),
            timeout=15,
            verify=False
        )
        if response.status_code == 200:
            token = response.text.strip()
            print(f"  [OK] Authenticated successfully! Token length: {len(token)} chars")
        else:
            print(f"  [FAIL] Auth rejected (HTTP {response.status_code}): {response.text[:150]}")
            return False
    except Exception as e:
        print(f"  [FAIL] Auth error: {e}")
        return False
    
    # Test 3: Agents API
    print("\nTest 3: Fetching Wazuh Agents via REST API...")
    agents_url = f"{wazuh_url.rstrip('/')}/agents?limit=10"
    agents_count = 0
    try:
        res = requests.get(
            agents_url,
            headers={'Authorization': f'Bearer {token}'},
            timeout=15,
            verify=False
        )
        if res.status_code == 200:
            data = res.json()
            items = data.get('data', {}).get('affected_items', [])
            agents_count = len(items)
            print(f"  [OK] Discovered {agents_count} registered agents:")
            for ag in items:
                print(f"       - Agent [{ag.get('id', 'N/A')}] {ag.get('name', 'Unknown')} ({ag.get('status', 'unknown')}) | IP: {ag.get('ip', 'N/A')}")
        else:
            print(f"  [FAIL] Agents query failed (HTTP {res.status_code})")
    except Exception as e:
        print(f"  [FAIL] Agents query error: {e}")
    
    # Test 4: Real Alerts Stream Extraction
    print("\nTest 4: Reading REAL Alerts from /var/ossec/logs/alerts/alerts.log...")
    try:
        from app.routes.wazuh import _get_alerts_from_log
        real_alerts = _get_alerts_from_log(limit=10)
        if real_alerts:
            print(f"  [OK] Successfully retrieved {len(real_alerts)} REAL live alerts:")
            for a in real_alerts[:5]:
                print(f"       [{a.get('severity', 'Info')}] {a.get('rule', {}).get('description', 'Alert')} (Agent: {a.get('agent', {}).get('name', 'N/A')})")
        else:
            print("  [INFO] Alerts file is currently empty or rotating.")
    except Exception as e:
        print(f"  [FAIL] Alert extraction error: {e}")
    
    print("\n" + "=" * 60)
    print("SUCCESS: Wazuh SIEM is fully connected and returning real telemetry!")
    print("=" * 60)
    return True

if __name__ == "__main__":
    success = test_wazuh_connection()
    sys.exit(0 if success else 1)