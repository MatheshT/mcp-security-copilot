#!/usr/bin/env python3
"""
Test various Wazuh API endpoints to find working alerts endpoint
"""

import requests
import base64
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def test_wazuh_endpoints():
    """Test various Wazuh API endpoints"""
    
    wazuh_url = os.getenv('WAZUH_API_URL')
    username = os.getenv('WAZUH_USERNAME')
    password = os.getenv('WAZUH_PASSWORD')
    
    print("=" * 60)
    print("Wazuh API Endpoint Testing")
    print("=" * 60)
    print(f"URL: {wazuh_url}")
    print(f"Username: {username}")
    print()
    
    # Authenticate first
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
            print(f"✅ Authentication successful")
            print(f"   Token: {token[:50]}...")
        else:
            print(f"❌ Authentication failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Authentication error: {e}")
        return False
    
    # Test various endpoints
    endpoints = [
        # Direct endpoints (like agents)
        'agents',
        'alerts',
        'events',
        
        # API v4 endpoints
        'api/v4/agents',
        'api/v4/alerts',
        'api/v4/events',
        'api/v4/manager/logs/alerts',
        'api/v4/manager/logs/events',
        'api/v4/manager/logs/summary',
        
        # Manager endpoints
        'manager/logs/alerts',
        'manager/logs/events',
        'manager/logs/summary',
        'manager/logs',
        
        # Alternative endpoints
        'security/events',
        'vulnerabilities',
    ]
    
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }
    
    working_endpoints = []
    
    for endpoint in endpoints:
        try:
            url = f"{wazuh_url.rstrip('/')}/{endpoint}"
            print(f"\nTesting: {endpoint}")
            print(f"URL: {url}")
            
            response = requests.get(url, headers=headers, params={'limit': 10}, timeout=5, verify=False)
            print(f"Status: {response.status_code}")
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    print(f"Response type: {type(data)}")
                    
                    if isinstance(data, dict):
                        print(f"Keys: {list(data.keys())[:10]}")
                        
                        # Check for alerts data
                        if 'data' in data:
                            print(f"Data type: {type(data['data'])}")
                            if isinstance(data['data'], dict):
                                print(f"Data keys: {list(data['data'].keys())}")
                                if 'affected_items' in data['data']:
                                    print(f"Affected items: {len(data['data']['affected_items'])}")
                                    if data['data']['affected_items']:
                                        print(f"Sample item: {str(data['data']['affected_items'][0])[:200]}")
                                        working_endpoints.append(endpoint)
                                elif 'items' in data['data']:
                                    print(f"Items: {len(data['data']['items'])}")
                                    if data['data']['items']:
                                        print(f"Sample item: {str(data['data']['items'][0])[:200]}")
                                        working_endpoints.append(endpoint)
                        elif 'items' in data:
                            print(f"Items: {len(data['items'])}")
                            if data['items']:
                                print(f"Sample item: {str(data['items'][0])[:200]}")
                                working_endpoints.append(endpoint)
                        elif 'alerts' in data:
                            print(f"Alerts: {len(data['alerts'])}")
                            if data['alerts']:
                                print(f"Sample alert: {str(data['alerts'][0])[:200]}")
                                working_endpoints.append(endpoint)
                    elif isinstance(data, list):
                        print(f"List length: {len(data)}")
                        if data:
                            print(f"Sample item: {str(data[0])[:200]}")
                            working_endpoints.append(endpoint)
                    
                    print("✅ Working endpoint")
                    
                except Exception as e:
                    print(f"JSON parse error: {e}")
                    print(f"Raw response: {response.text[:200]}")
            else:
                print(f"❌ Failed: {response.text[:100]}")
                
        except Exception as e:
            print(f"❌ Error: {e}")
    
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Working endpoints: {len(working_endpoints)}")
    for endpoint in working_endpoints:
        print(f"  - {endpoint}")
    
    if working_endpoints:
        print(f"\n✅ RECOMMENDED: Use '{working_endpoints[0]}' for alerts")
    else:
        print("\n❌ No working endpoints found")
    
    return len(working_endpoints) > 0

if __name__ == "__main__":
    import sys
    success = test_wazuh_endpoints()
    sys.exit(0 if success else 1)