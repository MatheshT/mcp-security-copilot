# SentinelAI X - PowerShell One-Click Launcher
$ErrorActionPreference = "Continue"

Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host "               SENTINELAI X - MCP SECURITY COPILOT v2.0" -ForegroundColor White
Write-Host "            Enterprise Autonomous SOC Analyst & Cyber Range" -ForegroundColor Yellow
Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host ""

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# 1. Check Python
$PythonExe = Join-Path $ScriptDir ".venv\Scripts\python.exe"
if (-not (Test-Path $PythonExe)) {
    Write-Host "[!] .venv Python not found. Falling back to system python..." -ForegroundColor Yellow
    $PythonExe = "python"
}
Write-Host "[OK] Python Engine : $PythonExe" -ForegroundColor Green

# 2. Check Node
$NodeCmd = Get-Command node -ErrorAction SilentlyContinue
if (-not $NodeCmd) {
    Write-Host "[ERROR] Node.js is not found in PATH. Please install Node.js (v18+)" -ForegroundColor Red
    Pause
    Exit 1
}
Write-Host "[OK] Node.js Engine: Detected" -ForegroundColor Green

# 3. Free ports
Write-Host "[*] Checking network ports 8000 and 5173..." -ForegroundColor Gray
$busyConnections = Get-NetTCPConnection -LocalPort 8000, 5173 -ErrorAction SilentlyContinue
if ($busyConnections) {
    foreach ($conn in $busyConnections) {
        if ($conn.OwningProcess -gt 0) {
            Write-Host "[*] Killing process on port $($conn.LocalPort) (PID: $($conn.OwningProcess))..." -ForegroundColor Yellow
            Stop-Process -Id $conn.OwningProcess -Force -ErrorAction SilentlyContinue
        }
    }
}

# 4. Start Backend
Write-Host "`n[1/3] Starting FastAPI SOC Backend Server..." -ForegroundColor Cyan
$BackendDir = Join-Path $ScriptDir "backend"
$backendProc = Start-Process -FilePath "cmd.exe" -ArgumentList "/k title SentinelAI Backend && cd /d `"$BackendDir`" && set PYTHONPATH=`"$BackendDir`" && `"$PythonExe`" -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload" -PassThru

# 5. Start Frontend
Write-Host "[2/3] Starting React Vite SOC Dashboard..." -ForegroundColor Cyan
$FrontendDir = Join-Path $ScriptDir "frontend"
$frontendProc = Start-Process -FilePath "cmd.exe" -ArgumentList "/k title SentinelAI Frontend && cd /d `"$FrontendDir`" && npm run dev -- --host 127.0.0.1 --port 5173" -PassThru

# 6. Wait & Launch Browser
Write-Host "[3/3] Waiting for servers to initialize..." -ForegroundColor Gray
Start-Sleep -Seconds 4

Write-Host "[*] Launching browser to http://localhost:5173 ..." -ForegroundColor Green
Start-Process "http://localhost:5173"

Write-Host "`n===============================================================================" -ForegroundColor Green
Write-Host "            >>> SENTINELAI X IS RUNNING SUCCESSFULLY! <<<" -ForegroundColor White
Write-Host "===============================================================================" -ForegroundColor Green
Write-Host " - Frontend Dashboard   : http://localhost:5173" -ForegroundColor White
Write-Host " - Backend API Engine   : http://localhost:8000" -ForegroundColor White
Write-Host " - Swagger API Docs     : http://localhost:8000/api/docs" -ForegroundColor White
Write-Host " - Cyber Range Simulator: http://localhost:5173 (Click '⚡ Cyber Range Simulator')" -ForegroundColor Yellow
Write-Host " - SOAR Active Defense  : http://localhost:5173 (Click '🛡️ SOAR & Active Defense')" -ForegroundColor Yellow
Write-Host " - MITRE ATT&CK Matrix  : http://localhost:5173 (Click '🗺️ MITRE ATT&CK Matrix')" -ForegroundColor Yellow
Write-Host "===============================================================================" -ForegroundColor Green
Write-Host "`nPress Enter to stop all servers and exit..." -ForegroundColor Gray
Read-Host

Write-Host "[*] Terminating background processes..." -ForegroundColor Gray
Stop-Process -Id $backendProc.Id -Force -ErrorAction SilentlyContinue
Stop-Process -Id $frontendProc.Id -Force -ErrorAction SilentlyContinue
Write-Host "[OK] Servers stopped cleanly." -ForegroundColor Green
