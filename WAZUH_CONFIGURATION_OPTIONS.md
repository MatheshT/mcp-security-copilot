# Wazuh Configuration Options

## Current Status
❌ No local Wazuh installation found on this machine
❌ Previous Wazuh server (192.168.1.7) is not reachable
✅ Your machine IPs: 192.168.56.1, 10.15.71.30

## Configuration Options

### Option 1: Install Local Wazuh (Recommended for Testing)
**Best for**: Development, testing, and learning

#### Steps:
1. **Install Wazuh Manager (Linux VM or Docker)**
   ```bash
   # Using Docker (easiest)
   docker run -d --name wazuh-manager \
     -e WAZUH_MANAGER_IP=192.168.56.1 \
     -p 55000:55000 \
     -p 1514:1514/udp \
     wazuh/wazuh-manager:4.8.0
   ```

2. **Get Default Credentials**
   - Username: `wazuh-wui`
   - Password: `wazuh-wui` (or check Wazuh documentation)

3. **Configure Backend**
   ```env
   WAZUH_API_URL=https://192.168.56.1:55000
   WAZUH_USERNAME=wazuh-wui
   WAZUH_PASSWORD=wazuh-wui
   ```

### Option 2: Connect to Existing Wazuh Server
**Best for**: Production environments with existing Wazuh deployment

#### Steps:
1. **Get Your Wazuh Server Details**
   - Server IP: `YOUR_WAZUH_SERVER_IP`
   - API Port: `55000` (default)
   - Username: `YOUR_USERNAME`
   - Password: `YOUR_PASSWORD`

2. **Test Connection**
   ```bash
   cd backend
   python test_wazuh_connection.py
   ```

3. **Update Configuration**
   ```env
   WAZUH_API_URL=https://YOUR_WAZUH_SERVER_IP:55000
   WAZUH_USERNAME=YOUR_USERNAME
   WAZUH_PASSWORD=YOUR_PASSWORD
   ```

### Option 3: Use Wazuh Cloud
**Best for**: Cloud-based security monitoring

#### Steps:
1. **Sign up for Wazuh Cloud** at https://wazuh.com/cloud/

2. **Get Cloud Instance Details**
   - Cloud URL: `https://YOUR_INSTANCE.wazuh.com`
   - API credentials from Wazuh Cloud dashboard

3. **Configure Backend**
   ```env
   WAZUH_API_URL=https://YOUR_INSTANCE.wazuh.com
   WAZUH_USERNAME=YOUR_CLOUD_USERNAME
   WAZUH_PASSWORD=YOUR_CLOUD_PASSWORD
   ```

### Option 4: Mock Wazuh Data (Temporary Solution)
**Best for**: Testing UI without real Wazuh server

#### Steps:
1. **Keep sample data mode active**
2. **Focus on UI testing and answerable features**
3. **Configure real Wazuh later when available**

## Quick Start: Docker Installation (Recommended)

### 1. Install Docker
```bash
# Download Docker Desktop for Windows
# https://www.docker.com/products/docker-desktop
```

### 2. Run Wazuh Manager
```bash
docker run -d --name wazuh-manager \
  -e WAZUH_MANAGER_IP=192.168.56.1 \
  -p 55000:55000 \
  -p 1514:1514/udp \
  wazuh/wazuh-manager:4.8.0
```

### 3. Wait for Wazuh to Start
```bash
docker logs -f wazuh-manager
# Wait until you see "Wazuh API started"
```

### 4. Configure Backend
```env
WAZUH_API_URL=https://192.168.56.1:55000
WAZUH_USERNAME=wazuh-wui
WAZUH_PASSWORD=wazuh-wui
```

### 5. Test Connection
```bash
cd backend
python test_wazuh_connection.py
```

### 6. Restart Backend
```bash
cd backend
python -m uvicorn app.main:app --host 0.0.0.0 --port 8001
```

## Network Notes

Your machine has these IP addresses:
- **192.168.56.1** - Virtual network (good for Docker)
- **10.15.71.30** - Main network (good for LAN connections)

Use the appropriate IP based on your Wazuh server location.

## Need Help?

1. **Wazuh Documentation**: https://documentation.wazuh.com/
2. **Wazuh Community**: https://wazuh.com/community/
3. **Setup Guide**: See WAZUH_SETUP_GUIDE.md for detailed instructions

## Current Recommendation

**Option 1 (Docker)** is recommended for quick setup and testing. It provides:
- Easy installation
- Local testing environment
- Real alerts from Wazuh
- Complete SOC workflow testing