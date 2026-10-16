#!/usr/bin/env python3
"""
Test the API filter with more data to find error/warning logs
"""
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend'))

os.environ['WAZUH_URL'] = 'https://192.168.56.101:55000'
os.environ['WAZUH_USERNAME'] = 'wazuh-wui'
os.environ['WAZUH_PASSWORD'] = 'wazuh-wui'
os.environ['WAZUH_VERIFY_SSL'] = 'false'

from app.routes.wazuh import wazuh_client, filter_alerts_by_severity, get_numeric_level
import json

def test_api_filter_extended():
    """Test the API filter with more data"""
    
    print("Testing API Filter with Extended Data...")
    print("="*60)
    
    # Authenticate
    print("\nAuthenticating...")
    if wazuh_client.authenticate():
        print("[OK] Authentication successful")
    else:
        print("[FAIL] Authentication failed")
        return
    
    # Get more manager logs
    print("\nGetting manager logs (500 max)...")
    data = wazuh_client.make_request("manager/logs", params={"limit": 500})
    
    if data and isinstance(data, dict) and 'data' in data:
        if 'affected_items' in data['data']:
            raw_logs = data['data']['affected_items']
            print(f"[OK] Retrieved {len(raw_logs)} log entries")
            
            # Convert to alerts
            alerts = []
            level_counts = {}
            
            for log in raw_logs:
                log_level = log.get("level", "info")
                numeric_level = get_numeric_level(log_level) if isinstance(log_level, str) else log_level
                
                # Count levels
                if numeric_level not in level_counts:
                    level_counts[numeric_level] = 0
                level_counts[numeric_level] += 1
                
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
                alerts.append(alert)
            
            print(f"\nConverted {len(alerts)} alerts")
            print(f"Level distribution: {level_counts}")
            
            # Test filtering
            print("\n" + "="*60)
            print("Testing severity filters...")
            
            for severity in ['critical', 'high', 'medium', 'low']:
                filtered = filter_alerts_by_severity(alerts, severity)
                print(f"\n{severity.upper()} filter: {len(filtered)} alerts")
                if filtered:
                    for alert in filtered[:3]:  # Show first 3
                        print(f"  Level: {alert['level']}, Description: {alert['rule']['description'][:60]}...")

if __name__ == "__main__":
    test_api_filter_extended()
