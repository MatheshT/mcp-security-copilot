import sys
sys.path.append('C:\\Users\\Admin\\Downloads\\MCP-Security-Copilot\\backend')

from app.routes.wazuh import wazuh_client

print('Testing Wazuh agents endpoint...')
try:
    # Test agents endpoint
    agents_data = wazuh_client.make_request("agents")
    
    if 'data' in agents_data and 'affected_items' in agents_data['data']:
        agents = agents_data['data']['affected_items']
        print(f'Successfully retrieved {len(agents)} agents from Wazuh')
        
        # Print first few agents
        for i, agent in enumerate(agents[:3]):
            print(f'\nAgent {i+1}:')
            print(f'  ID: {agent.get("id")}')
            print(f'  Name: {agent.get("name")}')
            print(f'  Status: {agent.get("status")}')
            print(f'  IP: {agent.get("ip")}')
            print(f'  OS: {agent.get("os", {}).get("name")} {agent.get("os", {}).get("version")}')
    else:
        print('Response structure unexpected')
        print(f'Response: {agents_data}')
        
except Exception as e:
    print(f'Error retrieving agents: {e}')