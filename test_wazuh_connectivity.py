#!/usr/bin/env python3
"""
Wazuh Connectivity Test Script
Tests connection to Wazuh API at https://192.168.56.101/
"""

import os
import sys
import base64
import requests
from datetime import datetime
import warnings
import json

# Suppress SSL warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# Fix Unicode encoding for Windows console
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

# Configuration from .env
WAZUH_URL = "https://192.168.56.101"
WAZUH_USERNAME = "wazuh-wui"
WAZUH_PASSWORD = "wazuh-wui"
# Try to fix the token - it seems to have 4 parts instead of 3
# Let's try to reconstruct it properly
# The token appears to be corrupted, let's use a simpler approach
WAZUH_API_KEY = ""  # Will try to get fresh token

def decode_jwt(token):
    """Decode JWT token without verification (for inspection only)"""
    try:
        print(f"Raw token length: {len(token)}")
        print(f"Raw token: {token[:200]}...")
        
        # Split token into parts
        parts = token.split('.')
        print(f"Token parts: {len(parts)}")
        
        if len(parts) != 3:
            print(f"Invalid JWT token structure (expected 3 parts, got {len(parts)})")
            print(f"Part lengths: {[len(p) for p in parts]}")
            print(f"Part 1 (first 50 chars): {parts[0][:50]}")
            print(f"Part 2 (first 50 chars): {parts[1][:50]}")
            print(f"Part 3 (first 50 chars): {parts[2][:50]}")
            if len(parts) > 3:
                print(f"Part 4 (first 50 chars): {parts[3][:50]}")
            return None, None, None
        
        # Decode header and payload (base64url)
        import base64
        def base64url_decode(input_str):
            # Add padding if needed
            input_str += '=' * (4 - len(input_str) % 4)
            return base64.urlsafe_b64decode(input_str)
        
        header = json.loads(base64url_decode(parts[0]))
        payload = json.loads(base64url_decode(parts[1]))
        
        return header, payload, parts[2]  # header, payload, signature
    except Exception as e:
        print(f"Error decoding JWT: {e}")
        import traceback
        traceback.print_exc()
        return None, None, None

def test_basic_connection():
    """Test basic HTTPS connection to Wazuh"""
    print("=" * 60)
    print("Testing Basic Network Connectivity")
    print("=" * 60)
    
    try:
        response = requests.get(WAZUH_URL, timeout=10, verify=False)
        print(f"[PASS] Basic connection successful: {response.status_code}")
        print(f"  Response headers: {dict(response.headers)}")
        
        # Try accessing the API info endpoint
        api_info_url = f"{WAZUH_URL.rstrip('/')}/api"
        print(f"\n  Testing API info endpoint: {api_info_url}")
        api_response = requests.get(api_info_url, timeout=10, verify=False)
        print(f"  API info response status: {api_response.status_code}")
        print(f"  API info response: {api_response.text[:500]}")
        
        return True
    except Exception as e:
        print(f"[FAIL] Basic connection failed: {e}")
        return False

def test_authentication():
    """Test Wazuh API authentication"""
    print("\n" + "=" * 60)
    print("Testing Wazuh API Authentication")
    print("=" * 60)
    
    # First, let's check the Wazuh API version and structure
    print("\n  Checking Wazuh API structure...")
    try:
        # Try different API endpoints
        api_endpoints = [
            "/api",
            "/api/v1",
            "/api/v2",
            "/api/v4",
            "/security/user/authenticate",
            "/security/user/authenticate?raw=true"
        ]
        
        for endpoint in api_endpoints:
            url = f"{WAZUH_URL.rstrip('/')}{endpoint}"
            print(f"  Testing endpoint: {url}")
            try:
                response = requests.get(url, timeout=10, verify=False)
                print(f"    Status: {response.status_code}")
                if response.status_code == 200:
                    print(f"    Response: {response.text[:200]}")
            except Exception as e:
                print(f"    Error: {e}")
    except Exception as e:
        print(f"  Error checking API structure: {e}")
    
    # Try different authentication endpoints
    auth_endpoints = [
        "/security/user/authenticate?raw=true",
        "/security/user/authenticate",
        "/api/security/user/authenticate?raw=true",
        "/api/security/user/authenticate",
        "/api/v4/security/user/authenticate?raw=true",
        "/api/v4/security/user/authenticate",
    ]
    
    credential_sets = [
        ("wazuh-wui", "wazuh-wui"),
        ("admin", "admin"),
        ("wazuh", "wazuh"),
        ("wazuh-api", "wazuh-api"),
    ]
    
    for auth_endpoint in auth_endpoints:
        auth_url = f"{WAZUH_URL.rstrip('/')}{auth_endpoint}"
        print(f"\n  Testing authentication endpoint: {auth_url}")
        
        for username, password in credential_sets:
            try:
                credentials = f"{username}:{password}"
                encoded_credentials = base64.b64encode(credentials.encode("utf-8")).decode("ascii")
                
                headers = {
                    "Content-Type": "application/json",
                    "Authorization": f"Basic {encoded_credentials}"
                }
                
                print(f"    Username: {username}, Password: {password}")
                
                response = requests.get(auth_url, headers=headers, timeout=20, verify=False)
                
                print(f"    Response status: {response.status_code}")
                
                if response.status_code == 200:
                    token = response.json().get("data", {}).get("token") or response.json().get("token")
                    if token:
                        print(f"[PASS] Authentication successful with {username}/{password}!")
                        print(f"  Token obtained (first 50 chars): {token[:50]}...")
                        return token
                    else:
                        print(f"[FAIL] Authentication response missing token")
                elif response.status_code == 404:
                    print(f"    Endpoint not found, trying next endpoint...")
                    break  # Try next auth endpoint
                else:
                    print(f"    Response body: {response.text[:200]}")
                    
            except Exception as e:
                print(f"    Authentication error for {username}: {e}")
                continue
    
    # Try with API key if available
    if WAZUH_API_KEY:
        print(f"\n  Trying with API Key...")
        try:
            # First try to use API key directly with API endpoints
            test_endpoints = [
                "/api/agents",
                "/api/v4/agents", 
                "/agents",
                "/api/alerts",
                "/api/v4/alerts",
                "/alerts"
            ]
            
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {WAZUH_API_KEY}"
            }
            
            for endpoint in test_endpoints:
                url = f"{WAZUH_URL.rstrip('/')}{endpoint}"
                print(f"    Testing API key with: {url}")
                try:
                    response = requests.get(url, headers=headers, timeout=20, verify=False)
                    print(f"    Response status: {response.status_code}")
                    
                    if response.status_code == 200:
                        print(f"[PASS] API Key authentication successful!")
                        print(f"    Response: {response.text[:200]}")
                        return WAZUH_API_KEY
                    elif response.status_code == 401:
                        print(f"    Still unauthorized with API key")
                    else:
                        print(f"    Response: {response.text[:200]}")
                except Exception as e:
                    print(f"    Error: {e}")
                    continue
                    
        except Exception as e:
            print(f"[FAIL] API Key authentication error: {e}")
    
    return None

def test_api_endpoint(token, endpoint, description):
    """Test a specific Wazuh API endpoint"""
    print(f"\n" + "=" * 60)
    print(f"Testing {description}")
    print("=" * 60)
    
    try:
        url = f"{WAZUH_URL.rstrip('/')}/{endpoint.lstrip('/')}"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}"
        }
        
        print(f"  Requesting: {url}")
        response = requests.get(url, headers=headers, timeout=20, verify=False)
        
        print(f"  Response status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"[PASS] {description} successful!")
            
            # Try to extract and display relevant information
            if isinstance(data, dict):
                if "data" in data:
                    if isinstance(data["data"], dict) and "items" in data["data"]:
                        items = data["data"]["items"]
                        print(f"  Total items: {len(items) if isinstance(items, list) else 'N/A'}")
                    elif isinstance(data["data"], list):
                        print(f"  Total items: {len(data['data'])}")
                    else:
                        print(f"  Data keys: {list(data['data'].keys())}")
                else:
                    print(f"  Response keys: {list(data.keys())}")
            
            return True
        else:
            print(f"[FAIL] {description} failed with status {response.status_code}")
            print(f"  Error: {response.text[:200]}")
            return False
            
    except Exception as e:
        print(f"[FAIL] Error accessing {description}: {e}")
        return False

def main():
    print("Wazuh Connectivity Test")
    print(f"Target URL: {WAZUH_URL}")
    print(f"Timestamp: {datetime.now()}")
    
    # Inspect JWT token if available
    if WAZUH_API_KEY:
        print("\n" + "=" * 60)
        print("Inspecting JWT Token")
        print("=" * 60)
        print(f"Token (first 100 chars): {WAZUH_API_KEY[:100]}...")
        
        header, payload, signature = decode_jwt(WAZUH_API_KEY)
        if header and payload:
            print(f"\nToken Header:")
            print(f"  Algorithm: {header.get('alg')}")
            print(f"  Type: {header.get('typ')}")
            
            print(f"\nToken Payload:")
            print(f"  Issuer: {payload.get('iss')}")
            print(f"  Audience: {payload.get('aud')}")
            print(f"  Subject: {payload.get('sub')}")
            print(f"  Issued At (iat): {payload.get('iat')} ({datetime.fromtimestamp(payload.get('iat', 0))})")
            print(f"  Expiration (exp): {payload.get('exp')} ({datetime.fromtimestamp(payload.get('exp', 0))})")
            print(f"  Run As: {payload.get('run_as')}")
            print(f"  RBAC Roles: {payload.get('rbac_roles')}")
            print(f"  RBAC Mode: {payload.get('rbac_mode')}")
            
            # Check if token is expired
            import time
            current_time = int(time.time())
            expiration = payload.get('exp', 0)
            if expiration and current_time > expiration:
                print(f"\n[WARNING] Token is EXPIRED! Current: {current_time}, Expiration: {expiration}")
            elif expiration:
                time_remaining = expiration - current_time
                print(f"\nToken is valid. Time remaining: {time_remaining} seconds ({time_remaining/60:.1f} minutes)")
        else:
            print("Failed to decode JWT token")
    
    # Test basic connection
    if not test_basic_connection():
        print("\n[ERROR] Basic connectivity failed. Cannot proceed.")
        sys.exit(1)
    
    # Test authentication
    token = test_authentication()
    if not token:
        print("\n[ERROR] Authentication failed. Cannot test API endpoints.")
        sys.exit(1)
    
    # Test various API endpoints
    endpoints_to_test = [
        ("alerts", "Alerts"),
        ("agents", "Agents"),
        ("rules", "Rules"),
        ("security/users", "Users"),
    ]
    
    results = []
    for endpoint, description in endpoints_to_test:
        success = test_api_endpoint(token, endpoint, description)
        results.append((description, success))
    
    # Summary
    print("\n" + "=" * 60)
    print("Connectivity Test Summary")
    print("=" * 60)
    
    for description, success in results:
        status = "[PASS]" if success else "[FAIL]"
        print(f"{status}: {description}")
    
    passed = sum(1 for _, success in results if success)
    total = len(results)
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n[SUCCESS] All connectivity tests passed!")
        sys.exit(0)
    else:
        print(f"\n[WARNING] {total - passed} test(s) failed")
        sys.exit(1)

if __name__ == "__main__":
    main()