#!/usr/bin/env python3
"""
Test the API endpoint directly to see what's happening
"""
import requests
import json

def test_api_direct():
    """Test the API endpoint directly"""
    
    print("Testing API Endpoint Directly...")
    print("="*60)
    
    # Test all alerts
    print("\nTesting all alerts (limit=10)...")
    response = requests.get("http://localhost:8000/api/detection/wazuh/alerts?severity=all&limit=10", verify=False)
    print(f"Status: {response.status_code}")
    if response.status_code == 200:
        data = response.json()
        print(f"Total alerts: {data.get('total_alerts', 0)}")
        print(f"Severity filter: {data.get('severity_filter', 'N/A')}")
        
        if data.get('alerts'):
            print(f"\nFirst alert structure:")
            print(json.dumps(data['alerts'][0], indent=2))
        
        print(f"\nAlert levels:")
        for alert in data.get('alerts', []):
            level = alert.get('level', alert.get('rule', {}).get('level', 'N/A'))
            print(f"  Level: {level}, Description: {alert.get('rule', {}).get('description', 'N/A')[:50]}...")
    
    # Test medium severity
    print("\n" + "="*60)
    print("Testing medium severity (limit=10)...")
    response = requests.get("http://localhost:8000/api/detection/wazuh/alerts?severity=medium&limit=10", verify=False)
    print(f"Status: {response.status_code}")
    if response.status_code == 200:
        data = response.json()
        print(f"Total alerts: {data.get('total_alerts', 0)}")
        print(f"Severity filter: {data.get('severity_filter', 'N/A')}")
        
        if data.get('alerts'):
            print(f"\nAlerts found:")
            for alert in data.get('alerts', []):
                level = alert.get('level', alert.get('rule', {}).get('level', 'N/A'))
                print(f"  Level: {level}, Description: {alert.get('rule', {}).get('description', 'N/A')[:50]}...")
        else:
            print("No alerts found")
    
    # Test critical severity
    print("\n" + "="*60)
    print("Testing critical severity (limit=10)...")
    response = requests.get("http://localhost:8000/api/detection/wazuh/alerts?severity=critical&limit=10", verify=False)
    print(f"Status: {response.status_code}")
    if response.status_code == 200:
        data = response.json()
        print(f"Total alerts: {data.get('total_alerts', 0)}")
        print(f"Severity filter: {data.get('severity_filter', 'N/A')}")
        
        if data.get('alerts'):
            print(f"\nAlerts found:")
            for alert in data.get('alerts', []):
                level = alert.get('level', alert.get('rule', {}).get('level', 'N/A'))
                print(f"  Level: {level}, Description: {alert.get('rule', {}).get('description', 'N/A')[:50]}...")
        else:
            print("No alerts found")

if __name__ == "__main__":
    test_api_direct()
