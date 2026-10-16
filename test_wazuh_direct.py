#!/usr/bin/env python3
"""
Direct test of Wazuh API connectivity
"""
import requests
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Wazuh configuration
WAZUH_URL = "https://192.168.56.101"
WAZUH_USERNAME = "wazuh-wui"
WAZUH_PASSWORD = "wazuh-wui"

print("Testing Wazuh API connectivity...")
print(f"URL: {WAZUH_URL}")
print(f"Username: {WAZUH_USERNAME}")
print()

# Test 1: Authentication
print("Test 1: Authentication")
auth_url = f"{WAZUH_URL}/security/user/authenticate?raw=true"
try:
    response = requests.get(auth_url, auth=(WAZUH_USERNAME, WAZUH_PASSWORD), 
                          verify=False, timeout=30)
    print(f"Status Code: {response.status_code}")
    if response.status_code == 200:
        token = response.text.strip()
        print(f"[OK] Authentication successful")
        print(f"Token (first 20 chars): {token[:20]}...")
    else:
        print(f"[FAIL] Authentication failed")
        print(f"Response: {response.text[:200]}")
except Exception as e:
    print(f"[FAIL] Error: {e}")

print()

# Test 2: Get agents (this was working before)
print("Test 2: Get Agents")
if response.status_code == 200:
    headers = {'Authorization': f'Bearer {token}'}
    agents_url = f"{WAZUH_URL}/agents"
    try:
        response = requests.get(agents_url, headers=headers, verify=False, timeout=30)
        print(f"Status Code: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            if 'data' in data and 'affected_items' in data['data']:
                agents = data['data']['affected_items']
                print(f"[OK] Retrieved {len(agents)} agents")
                for agent in agents[:2]:
                    print(f"  - Agent {agent.get('id')}: {agent.get('name')} ({agent.get('status')})")
            else:
                print(f"[FAIL] Unexpected response structure")
        else:
            print(f"[FAIL] Request failed")
    except Exception as e:
        print(f"[FAIL] Error: {e}")

print()

# Test 3: Try different alert endpoints
print("Test 3: Test Alert Endpoints")
alert_endpoints = [
    'api/v4/alerts',
    'manager/logs/alerts',
    'alerts',
    'logs/alerts',
    'manager/alerts',
]

for endpoint in alert_endpoints:
    try:
        url = f"{WAZUH_URL}/{endpoint}"
        print(f"Testing: {endpoint}")
        response = requests.get(url, headers=headers, verify=False, timeout=30, params={"limit": 10})
        print(f"  Status: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            if 'data' in data:
                if 'affected_items' in data['data']:
                    count = len(data['data']['affected_items'])
                    print(f"  [OK] Found {count} items in affected_items")
                elif 'items' in data['data']:
                    count = len(data['data']['items'])
                    print(f"  [OK] Found {count} items in items")
                else:
                    print(f"  Data keys: {list(data['data'].keys())}")
            else:
                print(f"  Response keys: {list(data.keys())}")
        else:
            print(f"  [FAIL] Status code: {response.status_code}")
    except Exception as e:
        print(f"  [FAIL] Error: {str(e)[:100]}")
    print()
