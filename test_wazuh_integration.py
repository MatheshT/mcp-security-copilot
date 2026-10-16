#!/usr/bin/env python3
"""
Test script for Wazuh integration
Tests log collection, alert retrieval, and severity filtering
"""
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend'))

from app.soc_analyst.autonomous_analyst import AutonomousSOCAnalyst
import asyncio

async def test_wazuh_integration():
    """Test Wazuh integration"""
    print("Testing Wazuh Integration...")
    
    # Create test configuration
    config = {
        "wazuh_url": "https://192.168.56.101",
        "wazuh_username": "wazuh-wui",
        "wazuh_password": "wazuh-wui"
    }
    
    # Create analyst instance
    analyst = AutonomousSOCAnalyst(config)
    
    # Test 1: Authenticate with Wazuh
    print("\nTest 1: Wazuh Authentication")
    auth_result = analyst._authenticate_wazuh()
    print(f"Authentication Result: {'SUCCESS' if auth_result else 'FAILED'}")
    
    if not auth_result:
        print("Authentication failed. Check Wazuh credentials and connection.")
        return
    
    # Test 2: Collect all alerts
    print("\nTest 2: Collect All Wazuh Alerts")
    all_alerts = await analyst.collect_wazuh_alerts(severity="all", time_range="24h", limit=50)
    print(f"Total Alerts Collected: {all_alerts.get('total_alerts', 0)}")
    print(f"Status: {all_alerts.get('status', 'unknown')}")
    
    # Test 3: Collect critical alerts
    print("\nTest 3: Collect Critical Wazuh Alerts")
    critical_alerts = await analyst.collect_wazuh_alerts(severity="critical", time_range="24h", limit=20)
    print(f"Critical Alerts Collected: {critical_alerts.get('total_alerts', 0)}")
    print(f"Status: {critical_alerts.get('status', 'unknown')}")
    
    # Test 4: Collect high alerts
    print("\nTest 4: Collect High Wazuh Alerts")
    high_alerts = await analyst.collect_wazuh_alerts(severity="high", time_range="24h", limit=20)
    print(f"High Alerts Collected: {high_alerts.get('total_alerts', 0)}")
    print(f"Status: {high_alerts.get('status', 'unknown')}")
    
    # Test 5: Collect medium alerts
    print("\nTest 5: Collect Medium Wazuh Alerts")
    medium_alerts = await analyst.collect_wazuh_alerts(severity="medium", time_range="24h", limit=20)
    print(f"Medium Alerts Collected: {medium_alerts.get('total_alerts', 0)}")
    print(f"Status: {medium_alerts.get('status', 'unknown')}")
    
    # Test 6: Collect low alerts
    print("\nTest 6: Collect Low Wazuh Alerts")
    low_alerts = await analyst.collect_wazuh_alerts(severity="low", time_range="24h", limit=20)
    print(f"Low Alerts Collected: {low_alerts.get('total_alerts', 0)}")
    print(f"Status: {low_alerts.get('status', 'unknown')}")
    
    # Test 7: Get alerts grouped by severity
    print("\nTest 7: Get Alerts Grouped by Severity")
    alerts_by_severity = await analyst.get_wazuh_alerts_by_severity(limit_per_severity=10, time_range="24h")
    print(f"Status: {alerts_by_severity.get('status', 'unknown')}")
    
    if "alerts_by_severity" in alerts_by_severity:
        for severity, data in alerts_by_severity["alerts_by_severity"].items():
            print(f"{severity.upper()} Alerts: {data.get('count', 0)}")
    
    print("\n" + "="*50)
    print("Wazuh Integration Test Complete!")
    print("="*50)

if __name__ == "__main__":
    asyncio.run(test_wazuh_integration())