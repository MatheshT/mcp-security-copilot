#!/usr/bin/env python3
"""
Debug script to find the correct Wazuh alerts endpoint
"""
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend'))

# Set environment variables for Wazuh connection
os.environ['WAZUH_URL'] = 'https://192.168.56.101'
os.environ['WAZUH_USERNAME'] = 'wazuh-wui'
os.environ['WAZUH_PASSWORD'] = 'wazuh-wui'
os.environ['WAZUH_VERIFY_SSL'] = 'false'

from app.routes.wazuh import wazuh_client
import json

def test_alert_endpoints():
    """Test various possible alert endpoints"""
    
    # First authenticate
    print("Authenticating with Wazuh...")
    if wazuh_client.authenticate():
        print("[OK] Authentication successful")
    else:
        print("[FAIL] Authentication failed")
        return
    
    # Test different alert endpoints
    alert_endpoints = [
        'api/v4/alerts',
        'manager/logs/alerts', 
        'alerts',
        'alerts/logs',
        'manager/alerts',
        'logs/alerts',
        'events/alerts',
        'security/events',
        'vulnerability/alerts',
        'api/v4/alerts/logs',
        'api/v4/logs/alerts',
        'agents/000/logs/alerts',  # Try with agent ID
        'syscheck',
        'rootcheck',
        'sca',
        'mitre',
    ]
    
    print("\n" + "="*60)
    print("Testing different alert endpoints...")
    print("="*60)
    
    for endpoint in alert_endpoints:
        try:
            print(f"\nTesting endpoint: {endpoint}")
            data = wazuh_client.make_request(endpoint, params={"limit": 10})
            
            if data:
                print(f"  [OK] Response received")
                print(f"  Status code: 200")
                
                # Check response structure
                if isinstance(data, dict):
                    if 'data' in data:
                        print(f"  Has 'data' field: Yes")
                        if 'affected_items' in data['data']:
                            items = data['data']['affected_items']
                            print(f"  Has 'affected_items': Yes ({len(items)} items)")
                            if items:
                                print(f"  Sample item: {json.dumps(items[0], indent=2)[:200]}...")
                        elif 'items' in data['data']:
                            items = data['data']['items']
                            print(f"  Has 'items': Yes ({len(items)} items)")
                            if items:
                                print(f"  Sample item: {json.dumps(items[0], indent=2)[:200]}...")
                        else:
                            print(f"  Data keys: {list(data['data'].keys())}")
                    else:
                        print(f"  Data keys: {list(data.keys())}")
                        print(f"  Sample: {json.dumps(data, indent=2)[:300]}...")
                else:
                    print(f"  Response type: {type(data)}")
                    print(f"  Sample: {str(data)[:200]}...")
                    
            else:
                print(f"  [FAIL] No response")
                
        except Exception as e:
            print(f"  [FAIL] Error: {str(e)[:100]}")
    
    # Test with parameters
    print("\n" + "="*60)
    print("Testing with different parameters...")
    print("="*60)
    
    test_params = [
        {"limit": 50},
        {"limit": 50, "offset": 0},
        {"limit": 50, "sort": "-timestamp"},
        {"limit": 50, "date": "2026-09-15"},
        {"limit": 50, "search": "level"},
    ]
    
    for params in test_params:
        try:
            print(f"\nTesting params: {params}")
            # Try the most common endpoint
            data = wazuh_client.make_request("api/v4/alerts", params=params)
            if data and isinstance(data, dict) and 'data' in data:
                if 'affected_items' in data['data']:
                    count = len(data['data']['affected_items'])
                    print(f"  [OK] Found {count} items")
                elif 'items' in data['data']:
                    count = len(data['data']['items'])
                    print(f"  [OK] Found {count} items")
                else:
                    print(f"  Response keys: {list(data['data'].keys())}")
            else:
                print(f"  ✗ No data found")
        except Exception as e:
            print(f"  [FAIL] Error: {str(e)[:100]}")

if __name__ == "__main__":
    test_alert_endpoints()
