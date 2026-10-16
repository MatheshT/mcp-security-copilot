import sys
sys.path.append('C:\\Users\\Admin\\Downloads\\MCP-Security-Copilot\\backend')

from app.routes.wazuh import wazuh_client

print('Testing Wazuh connection with fixed permissions...')
result = wazuh_client.authenticate()
print(f'Authentication: {"Success" if result else "Failed"}')

if result:
    print('JWT Token obtained successfully')
    print(f'Token length: {len(wazuh_client.token)} characters')
else:
    print('Authentication failed - check credentials and permissions')