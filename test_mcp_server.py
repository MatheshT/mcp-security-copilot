import sys
sys.path.append('C:\\Users\\Admin\\Downloads\\MCP-Security-Copilot\\backend')

from app.mcp.wazuh_mcp_server import wazuh_client

print('Testing MCP server Wazuh client...')
result = wazuh_client.authenticate()
print(f'Authentication: {"Success" if result else "Failed"}')

if result:
    print('MCP server can authenticate with Wazuh successfully')
    print(f'Token length: {len(wazuh_client.token)} characters')
else:
    print('MCP server authentication failed')