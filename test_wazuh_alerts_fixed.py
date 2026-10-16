#!/usr/bin/env python3
"""
Test the fixed Wazuh alerts endpoint
"""
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend'))

# Set environment variables for Wazuh connection
os.environ['WAZUH_URL'] = 'https://192.168.56.101:55000'
os.environ['WAZUH_USERNAME'] = 'wazuh-wui'
os.environ['WAZUH_PASSWORD'] = 'wazuh-wui'
os.environ['WAZUH_VERIFY_SSL'] = 'false'

from app.routes.wazuh import wazuh_client
import json

def test_alerts():
    """Test the fixed alerts endpoint"""
    
    print("Testing Wazuh Alerts Endpoint (Fixed)...")
    print("="*60)
    
    # First authenticate
    print("\nAuthenticating with Wazuh...")
    if wazuh_client.authenticate():
        print("[OK] Authentication successful")
    else:
        print("[FAIL] Authentication failed")
        return
    
    # Test the manager/logs endpoint
    print("\nTesting manager/logs endpoint...")
    try:
        params = {"limit": 10}
        data = wazuh_client.make_request("manager/logs", params=params)
        
        if data and isinstance(data, dict) and 'data' in data:
            if 'affected_items' in data['data']:
                logs = data['data']['affected_items']
                print(f"[OK] Retrieved {len(logs)} log entries")
                
                # Show first few entries
                print("\nSample log entries:")
                for i, log in enumerate(logs[:3]):
                    print(f"\nEntry {i+1}:")
                    print(f"  Timestamp: {log.get('timestamp')}")
                    print(f"  Tag: {log.get('tag')}")
                    print(f"  Level: {log.get('level')}")
                    print(f"  Description: {log.get('description', '')[:80]}...")
            else:
                print(f"[FAIL] No affected_items in response")
                print(f"Response keys: {list(data['data'].keys())}")
        else:
            print(f"[FAIL] Unexpected response structure")
            print(f"Response: {json.dumps(data, indent=2)[:500]}...")
            
    except Exception as e:
        print(f"[FAIL] Error: {e}")

if __name__ == "__main__":
    test_alerts()
