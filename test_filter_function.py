#!/usr/bin/env python3
"""
Test the filter function directly
"""
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend'))

from app.routes.wazuh import filter_alerts_by_severity, get_numeric_level
import json

def test_filter():
    """Test the filter function"""
    
    print("Testing Filter Function...")
    print("="*60)
    
    # Create test alerts
    test_alerts = [
        {
            "timestamp": "2026-09-15T15:29:28Z",
            "rule": {
                "level": 12,
                "description": "Error log",
                "groups": ["error"]
            },
            "agent": {"name": "wazuh-manager", "id": "000"},
            "level": 12
        },
        {
            "timestamp": "2026-09-15T15:29:28Z",
            "rule": {
                "level": 8,
                "description": "Warning log",
                "groups": ["warning"]
            },
            "agent": {"name": "wazuh-manager", "id": "000"},
            "level": 8
        },
        {
            "timestamp": "2026-09-15T15:29:28Z",
            "rule": {
                "level": 3,
                "description": "Info log",
                "groups": ["info"]
            },
            "agent": {"name": "wazuh-manager", "id": "000"},
            "level": 3
        }
    ]
    
    print("\nTest alerts:")
    for alert in test_alerts:
        print(f"  Level: {alert['level']}, Description: {alert['rule']['description']}")
    
    # Test different severity filters
    for severity in ['critical', 'high', 'medium', 'low']:
        filtered = filter_alerts_by_severity(test_alerts, severity)
        print(f"\n{severity.upper()} filter: {len(filtered)} alerts")
        for alert in filtered:
            print(f"  Level: {alert['level']}, Description: {alert['rule']['description']}")
    
    # Test with mixed string/numeric levels
    print("\n" + "="*60)
    print("Testing with mixed string/numeric levels...")
    
    mixed_alerts = [
        {
            "timestamp": "2026-09-15T15:29:28Z",
            "rule": {
                "level": "error",
                "description": "Error string",
                "groups": ["error"]
            },
            "agent": {"name": "wazuh-manager", "id": "000"},
            "level": "error"
        },
        {
            "timestamp": "2026-09-15T15:29:28Z",
            "rule": {
                "level": "warning",
                "description": "Warning string",
                "groups": ["warning"]
            },
            "agent": {"name": "wazuh-manager", "id": "000"},
            "level": "warning"
        },
        {
            "timestamp": "2026-09-15T15:29:28Z",
            "rule": {
                "level": "info",
                "description": "Info string",
                "groups": ["info"]
            },
            "agent": {"name": "wazuh-manager", "id": "000"},
            "level": "info"
        }
    ]
    
    print("\nMixed alerts:")
    for alert in mixed_alerts:
        print(f"  Level: {alert['level']} (type: {type(alert['level']).__name__}), Description: {alert['rule']['description']}")
    
    for severity in ['critical', 'high', 'medium', 'low']:
        filtered = filter_alerts_by_severity(mixed_alerts, severity)
        print(f"\n{severity.upper()} filter: {len(filtered)} alerts")
        for alert in filtered:
            print(f"  Level: {alert['level']}, Description: {alert['rule']['description']}")

if __name__ == "__main__":
    test_filter()
