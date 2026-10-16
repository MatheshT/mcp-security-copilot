# Wazuh Integration Setup Guide

## Current Status
The Wazuh server at `192.168.1.7` is not reachable. To display real Wazuh alerts, you need to configure your actual Wazuh server connection.

## Configuration Steps

### 1. Update Wazuh Server Credentials

Edit `backend/.env` file with your actual Wazuh server details:

```env
WAZUH_API_URL=https://YOUR_WAZUH_SERVER_IP:55000
WAZUH_USERNAME=YOUR_WAZUH_USERNAME
WAZUH_PASSWORD=YOUR_WAZUH_PASSWORD
```

### 2. Common Wazuh API Endpoints

- **Default API Port**: 55000
- **Default Username**: wazuh-wui
- **Authentication**: JWT token via `/security/user/authenticate`
- **Alerts Endpoint**: `/api/v4/alerts` or `/api/v4/manager/logs/alerts`

### 3. Test Wazuh Connection

Run this test script to verify your Wazuh connection:

```bash
cd backend
python test_wazuh_connection.py
```

### 4. Wazuh Server Requirements

- Wazuh server must be running and accessible
- API port (55000) must be open
- Valid user credentials with API access
- SSL certificate (can use self-signed with verify=False)

### 5. Alternative: Use Wazuh Cloud API

If using Wazuh Cloud, update the URL to your cloud instance:

```env
WAZUH_API_URL=https://YOUR_CLOUD_INSTANCE.wazuh.com
```

## Troubleshooting

### Connection Timeout
- Check if Wazuh server is running: `systemctl status wazuh-manager`
- Verify network connectivity: `ping YOUR_WAZUH_IP`
- Check firewall rules: `ufw status` or `firewall-cmd --list-all`

### Authentication Failed
- Verify username and password in Wazuh dashboard
- Check user has API permissions
- Ensure API user is created in Wazuh

### No Alerts Returned
- Check if Wazuh agents are reporting events
- Verify alert rules are active
- Check Wazuh logs: `/var/ossec/logs/logs.json`

## Current Fallback Behavior

When Wazuh is not available, the system displays sample security alerts to demonstrate functionality. Once your Wazuh connection is configured, real alerts will automatically replace the sample data.

## Enable Real Alerts

1. Update `backend/.env` with your Wazuh credentials
2. Restart the backend server
3. The alerts page will automatically fetch real Wazuh alerts
4. Sample alerts will be replaced with actual security events