#!/usr/bin/env python3
"""
Debug script to check alert structure
"""
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend'))

os.environ['WAZUH_URL'] = 'https://192.168.56.101:55000'
os.environ['WAZUH_USERNAME'] = 'wazuh-wui'
os.environ['WAZUH_PASSWORD'] = 'wazuh-wui'
os.environ['WAZUH_VERIFY_SSL'] = 'false'

from app.routes.wazuh import wazuh_client, get_numeric_level
import json

def test_alert_structure():
    """Test the alert structure"""
    
    print("Testing Alert Structure...")
    print("="*60)
    
    # Authenticate
    print("\nAuthenticating...")
    if wazuh_client.authenticate():
        print("[OK] Authentication successful")
    else:
        print("[FAIL] Authentication failed")
        return
    
    # Get manager logs
    print("\nGetting manager logs...")
    data = wazuh_client.make_request("manager/logs", params={"limit": 3})
    
    if data and isinstance(data, dict) and 'data' in data:
        if 'affected_items' in data['data']:
            logs = data['data']['affected_items']
            print(f"[OK] Retrieved {len(logs)} log entries")
            
            # Show structure
            print("\nSample log structure:")
            print(json.dumps(logs[0], indent=2))
            
            # Test conversion
            print("\n" + "="*60)
            print("Testing alert conversion...")
            for log in logs[:2]:
                log_level = log.get("level", "info")
                numeric_level = get_numeric_level(log_level) if isinstance(log_level, str) else log_level
                
                print(f"\nOriginal level: {log_level} (type: {type(log_level).__name__})")
                print(f"Numeric level: {numeric_level} (type: {type(numeric_level).__name__})")
                
                alert = {
                    "timestamp": log.get("timestamp"),
                    "rule": {
                        "level": numeric_level,
                        "description": log.get("description", ""),
                        "groups": [log.get("tag", "")]
                    },
                    "agent": {
                        "name": "wazuh-manager",
                        "id": "000"
                    },
                    "full_log": f"{log.get('tag', '')}: {log.get('description', '')}",
                    "location": "wazuh-manager",
                    "level": numeric_level
                }
                
                print(f"Alert structure: {json.dumps(alert, indent=2)}")

if __name__ == "__main__":
    test_alert_structure()
