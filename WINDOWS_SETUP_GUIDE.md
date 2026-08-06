# Windows Integration Setup Guide

## Current Status
✅ **Backend**: Running at http://localhost:8000  
✅ **Frontend**: Running at http://localhost:5173  
✅ **Windows Logs Integration**: Active  
✅ **Windows Defender Integration**: Active  

## Access the Application

1. **Open your browser and navigate to**: http://localhost:5173
2. You will see the Security Copilot Enterprise dashboard

## Windows Connection Options

### Option 1: Mock Data (Current - Already Working)
The system is currently using realistic mock data for Windows Event Logs and Windows Defender. This is perfect for testing and demonstration.

### Option 2: Real Windows Connection (Advanced)
To connect to your actual Windows machine:

#### Prerequisites:
- Windows 10/11 with administrative privileges
- PowerShell enabled
- Network connectivity between your Windows machine and this server

#### Setup Steps:

1. **Enable Windows Event Log Collection** (on your Windows machine):
   ```powershell
   # Run as Administrator
   winrm quickconfig
   Enable-PSRemoting -Force
   ```

2. **Configure Windows Defender API** (on your Windows machine):
   ```powershell
   # Enable Windows Defender API access
   Set-MpPreference -EnableControlledFolderAccess Enabled
   ```

3. **Update Environment Variables** (in this project):
   - Edit `backend/.env` file:
     ```
     WINDOWS_HOSTNAME=your-windows-pc-name
     WINDOWS_USERNAME=your-username
     ```

4. **Restart the backend server**:
   ```bash
   # Stop current server (Ctrl+C)
   # Restart with:
   cd backend
   python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
   ```

## Testing Guide

### Test 1: Windows Event Logs Integration

1. **Navigate to the Dashboard** (📊 Dashboard button in sidebar)
2. **Look for "Windows Logs" in the Tool Status section**
3. **Test via Chat Interface**:
   - Type in chat: "Check Windows security events"
   - You should see Windows event data with:
     - Event IDs (4625, 4624, 4740, etc.)
     - Severity levels (Critical, High, Medium, Low)
     - MITRE ATT&CK mappings
     - Hostname and username information

### Test 2: Windows Defender Integration

1. **Navigate to the Dashboard** (📊 Dashboard button in sidebar)
2. **Look for "Windows Defender" in the Tool Status section**
3. **Test via Chat Interface**:
   - Type in chat: "Check Windows Defender threats"
   - You should see threat data with:
     - Threat names (Trojan:Win32/Emotet, Ransom:Win32/WannaCrypt, etc.)
     - Severity levels
     - File paths
     - Detection status (Quarantined, Removed, etc.)

### Test 3: SOC Dashboard

1. **Click on "📊 Dashboard" in sidebar**
2. **You should see**:
   - Windows Events integration status
   - Windows Defender integration status
   - Tool status indicators showing "Online"
   - Recent investigations with Windows data

### Test 4: Complete Investigation Flow

1. **Start a new investigation** via chat:
   ```
   "Investigate failed login attempts from Windows Event Logs"
   ```
2. **Expected results**:
   - AI analyzes Windows security events
   - Shows event details (Event ID 4625 - Failed Login)
   - Provides MITRE ATT&CK mapping (T1110.001)
   - Suggests countermeasures

3. **Test Windows Defender investigation**:
   ```
   "Analyze recent Windows Defender threat detections"
   ```
4. **Expected results**:
   - AI shows detected threats
   - Displays threat severity and type
   - Shows file paths and action taken
   - Provides remediation recommendations

## Key Features to Test

### Windows Event Logs Features:
- ✅ Security events (failed logins, account changes)
- ✅ System events (service installations, scheduled tasks)
- ✅ Application events (crashes, errors)
- ✅ MITRE ATT&CK technique mappings
- ✅ Real-time event severity classification

### Windows Defender Features:
- ✅ Threat detection and classification
- ✅ Scan history tracking
- ✅ Quarantine management
- ✅ Protection status monitoring
- ✅ Real-time threat scoring

## Troubleshooting

### Frontend not loading:
- Check if frontend server is running: http://localhost:5173
- Restart frontend: `cd frontend && npm run dev`

### Backend not responding:
- Check if backend server is running: http://localhost:8000
- Restart backend: `cd backend && python -m uvicorn app.main:app --reload`

### Windows integrations not working:
- Check backend logs for errors
- Verify environment variables are set
- Test with mock data (default configuration)

## Next Steps

1. **Test with mock data first** (already configured)
2. **Explore the dashboard** and chat interface
3. **Try different investigation queries**
4. **Connect real Windows machine** (optional, requires setup)

## Quick Start Commands

```bash
# Start Backend
cd backend
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Start Frontend
cd frontend
npm run dev

# Access Application
# Browser: http://localhost:5173
```

Both servers are currently running and ready for testing!
