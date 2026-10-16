import sys
import os
import base64
import json
from pathlib import Path
from dotenv import load_dotenv

# Fix Unicode encoding for Windows console
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

# Add the backend directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Load backend environment variables
load_dotenv(Path(__file__).resolve().parent / '.env')

from app.mcp.wazuh_server import WazuhServer

def decode_jwt(token):
    """Decode JWT token without verification"""
    try:
        parts = token.split('.')
        if len(parts) >= 2:
            def base64url_decode(input_str):
                input_str += '=' * (4 - len(input_str) % 4)
                return base64.urlsafe_b64decode(input_str)
            
            header = json.loads(base64url_decode(parts[0]))
            payload = json.loads(base64url_decode(parts[1]))
            return header, payload
    except Exception as e:
        print(f"Error decoding JWT: {e}")
    return None, None

print('Testing Wazuh connection with project configuration...')

base_url = os.environ.get('WAZUH_URL', 'https://192.168.56.101:55000').rstrip('/')
username = os.environ.get('WAZUH_USERNAME', 'wazuh')
password = os.environ.get('WAZUH_PASSWORD', 'wazuh')

print(f'\n{"="*60}')
print(f'Testing with Wazuh URL: {base_url}')
print(f'{"="*60}')

os.environ['WAZUH_URL'] = base_url
os.environ['WAZUH_USERNAME'] = username
os.environ['WAZUH_PASSWORD'] = password

server = WazuhServer()

try:
    print(f'Wazuh URL: {server.base_url}')
    print(f'Username: {server.username}')
    print('Attempting authentication...')

    token = server._authenticate()

    if token:
        print('Authentication successful!')
        print(f'Token (first 50 chars): {token[:50]}')
        print(f'Token length: {len(token)}')

        # Decode token to see permissions
        header, payload = decode_jwt(token)
        if header and payload:
            print(f'\nToken Header: {header}')
            print(f'Token Payload: {payload}')

        # Try different API endpoints
        print('\nAttempting to get agents with different endpoints...')

        endpoints = [
            'agents',
            '/agents',
            'summary/agents',
            '/summary/agents',
            'security/agents',
            '/security/agents'
        ]

        for endpoint in endpoints:
            print(f'\nTrying endpoint: {endpoint}')
            try:
                result = server._request(endpoint, params={'limit': 10})
                if isinstance(result, dict):
                    print(f'Success! Result keys: {list(result.keys())}')
                else:
                    print('Success! Result returned')
                print(f'Success! Result: {result}')
                print(f'\n[SUCCESS] CONNECTION SUCCESSFUL with base URL: {base_url} and endpoint: {endpoint}')
                sys.exit(0)
            except Exception as e:
                print(f'Failed: {e}')
    else:
        print('Authentication failed - no token returned')

except Exception as e:
    print(f'Error with Wazuh URL {base_url}: {e}')

print('\n[ERROR] No successful connection found.')