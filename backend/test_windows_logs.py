from app.mcp.windows_logs_server import WindowsLogsServer

server = WindowsLogsServer()
result = server.get_security_events()

print(f'Status: {result.status}')
print(f'Data source: {result.data.get("data_source", "unknown")}')
print(f'Events count: {result.data.get("total_count", 0)}')
print(f'Details: {result.details}')