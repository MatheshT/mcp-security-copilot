#!/usr/bin/env python3
"""
Robust test script for Wazuh with retry logic
"""
import requests
import urllib3
import time

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

WAZUH_URL = "https://192.168.56.101:55000"
WAZUH_USERNAME = "wazuh-wui"
WAZUH_PASSWORD = "wazuh-wui"

def authenticate_with_retry(max_retries=3, delay=5):
    """Authenticate with retry logic"""
    for attempt in range(max_retries):
        try:
            print(f"Authentication attempt {attempt + 1}/{max_retries}...")
            auth_url = f"{WAZUH_URL}/security/user/authenticate?raw=true"
            response = requests.get(auth_url, auth=(WAZUH_USERNAME, WAZUH_PASSWORD), 
                                   verify=False, timeout=60)
            
            print(f"  Status code: {response.status_code}")
            
            if response.status_code == 200:
                token = response.text.strip()
                print(f"[OK] Authentication successful")
                print(f"Token (first 20 chars): {token[:20]}...")
                return token
            elif response.status_code == 503:
                print(f"[WARN] Server not ready (503), retrying in {delay}s...")
                time.sleep(delay)
            else:
                print(f"[FAIL] Status code: {response.status_code}")
                print(f"Response: {response.text[:200]}")
                if attempt < max_retries - 1:
                    time.sleep(delay)
        except Exception as e:
            print(f"[FAIL] Error: {e}")
            if attempt < max_retries - 1:
                time.sleep(delay)
    
    return None

def test_manager_logs(token):
    """Test manager/logs endpoint"""
    headers = {'Authorization': f'Bearer {token}'}
    print("\nTesting manager/logs endpoint...")
    
    try:
        response = requests.get(f"{WAZUH_URL}/manager/logs", headers=headers, 
                              verify=False, timeout=60, params={"limit": 5})
        print(f"Status code: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            if 'data' in data and 'affected_items' in data['data']:
                logs = data['data']['affected_items']
                print(f"[OK] Retrieved {len(logs)} log entries")
                
                print("\nSample entries:")
                for i, log in enumerate(logs[:3]):
                    print(f"\nEntry {i+1}:")
                    print(f"  Timestamp: {log.get('timestamp')}")
                    print(f"  Tag: {log.get('tag')}")
                    print(f"  Level: {log.get('level')}")
                    print(f"  Description: {log.get('description', '')[:60]}...")
                return True
            else:
                print(f"[FAIL] Unexpected response structure")
                return False
        else:
            print(f"[FAIL] Request failed: {response.text[:200]}")
            return False
    except Exception as e:
        print(f"[FAIL] Error: {e}")
        return False

def main():
    print("Robust Wazuh Test")
    print("="*60)
    
    # Authenticate with retry
    token = authenticate_with_retry()
    if not token:
        print("\n[FAIL] Could not authenticate after multiple attempts")
        return
    
    # Test manager logs
    if test_manager_logs(token):
        print("\n[SUCCESS] All tests passed!")
    else:
        print("\n[FAIL] Manager logs test failed")

if __name__ == "__main__":
    main()
