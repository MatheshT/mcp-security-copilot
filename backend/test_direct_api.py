#!/usr/bin/env python3
"""
Direct API test to see what Wazuh returns for alerts
"""

import requests
import base64
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def test_direct_api():
    """Test Wazuh API directly"""
    
    wazuh_url = os.getenv('WAZUH_API_URL')
    username = os.getenv('WAZUH_USERNAME')
    password = os.getenv('WAZUH_PASSWORD')
    
    print("=" * 60)
    print("Direct Wazuh API Test")
    print("=" * 60)
    print(f"URL: {wazuh_url}")
    print(f"Username: {username}")
    print()
    
    # Authenticate
    auth_url = f"{wazuh_url.rstrip('/')}/security/user/authenticate?raw=true"
    credentials = f"{username}:{password}"
    encoded_credentials = base64.b64encode(credentials.encode('utf-8')).decode('ascii')
    
    try:
        response = requests.post(
            auth_url,
            headers={'Content-Type': 'application/json', 'Authorization': f'Basic {encoded_credentials}'},
            timeout=10,
            verify=False
        )
        
        if response.status_code == 200:
            token = response.text.strip()
            print(f"Auth successful")
        else:
            print(f"Auth failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"Auth error: {e}")
        return False
    
    # Test alerts endpoint
    alerts_url = f"{wazuh_url.rstrip('/')}/alerts"
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }
    
    print(f"\nTesting alerts endpoint: {alerts_url}")
    try:
        response = requests.get(alerts_url, headers=headers, params={'limit': 10}, timeout=5, verify=False)
        print(f"Status: {response.status_code}")
        print(f"Response: {response.text[:500]}")
        
        if response.status_code == 200:
            try:
                data = response.json()
                print(f"Data type: {type(data)}")
                print(f"Data keys: {list(data.keys()) if isinstance(data, dict) else 'N/A'}")
                print(f"Full data: {data}")
            except:
                print("Could not parse JSON")
        
    except Exception as e:
        print(f"Error: {e}")
    
    # Test security/events endpoint
    events_url = f"{wazuh_url.rstrip('/')}/security/events"
    print(f"\nTesting security/events endpoint: {events_url}")
    try:
        response = requests.get(events_url, headers=headers, params={'limit': 10}, timeout=5, verify=False)
        print(f"Status: {response.status_code}")
        print(f"Response: {response.text[:500]}")
        
        if response.status_code == 200:
            try:
                data = response.json()
                print(f"Data type: {type(data)}")
                print(f"Data keys: {list(data.keys()) if isinstance(data, dict) else 'N/A'}")
                print(f"Full data: {data}")
            except:
                print("Could not parse JSON")
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_direct_api()