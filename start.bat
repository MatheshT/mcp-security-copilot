@echo off
setlocal enabledelayedexpansion
title SentinelAI X - MCP Security Copilot Launcher
cd /d "%~dp0"
color 0B

echo ===============================================================================
echo                SENTINELAI X - MCP SECURITY COPILOT v2.0
echo             Enterprise Autonomous SOC Analyst & Cyber Range
echo ===============================================================================
echo.

:: 1. Check Python
set "PYTHON_EXE=%~dp0.venv\Scripts\python.exe"
if not exist "%PYTHON_EXE%" (
    echo [!] Virtual environment python not found at .venv\Scripts\python.exe
    echo [*] Checking system python...
    where python >nul 2>nul
    if %errorlevel% neq 0 (
        color 0C
        echo [ERROR] Python is not installed or not in PATH. Please install Python 3.10+
        pause
        exit /b 1
    )
    set "PYTHON_EXE=python"
)
echo [OK] Python Engine : %PYTHON_EXE%

:: 1.5. Ensure Python Dependencies are Installed
echo [*] Verifying Python dependencies...
"%PYTHON_EXE%" -c "import fastapi, uvicorn, numpy, sklearn, pandas" >nul 2>nul
if %errorlevel% neq 0 (
    echo [!] Missing required dependencies. Installing from backend\requirements.txt...
    "%PYTHON_EXE%" -m pip install -r "%~dp0backend\requirements.txt"
    if %errorlevel% neq 0 (
        color 0C
        echo [ERROR] Failed to install backend dependencies.
        pause
        exit /b 1
    )
    echo [OK] Backend dependencies installed successfully.
) else (
    echo [OK] Python Dependencies: All verified
)

:: 2. Check Node.js
where node >nul 2>nul
if %errorlevel% neq 0 (
    color 0C
    echo [ERROR] Node.js is not found in PATH. Please install Node.js (v18+)
    pause
    exit /b 1
)
echo [OK] Node.js Engine: Detected

:: 3. Free ports 8000 and 5173 if busy
echo [*] Checking and preparing network ports (8000, 5173)...
for /f "tokens=5" %%a in ('netstat -aon 2^>nul ^| findstr ":8000 "') do (
    if "%%a" neq "0" (
        echo [*] Freeing port 8000 (PID: %%a)...
        taskkill /F /PID %%a >nul 2>&1
    )
)
for /f "tokens=5" %%a in ('netstat -aon 2^>nul ^| findstr ":5173 "') do (
    if "%%a" neq "0" (
        echo [*] Freeing port 5173 (PID: %%a)...
        taskkill /F /PID %%a >nul 2>&1
    )
)

:: 3.5. Ensure Wazuh SIEM VirtualBox VM is Running in Background
set "VBOX_MANAGE=C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
set "WAZUH_VM_NAME=Wazuh v4.14.7 OVA"
if exist "%VBOX_MANAGE%" (
    echo [*] Checking Wazuh SIEM VirtualBox VM status...
    "%VBOX_MANAGE%" list runningvms | findstr /C:"%WAZUH_VM_NAME%" >nul 2>&1
    if errorlevel 1 (
        echo [*] Starting "%WAZUH_VM_NAME%" silently in headless mode...
        "%VBOX_MANAGE%" startvm "%WAZUH_VM_NAME%" --type headless >nul 2>&1
        echo [OK] Wazuh SIEM VM started in background.
    ) else (
        echo [OK] Wazuh SIEM VM is active and running.
    )
)

:: 4. Start Backend Server
echo.
echo ===============================================================================
echo [1/3] Starting FastAPI SOC Backend Server...
echo ===============================================================================
start "SentinelAI Backend [Port 8000]" cmd /k "title SentinelAI Backend && cd /d "%~dp0backend" && set PYTHONPATH=%~dp0backend && "%PYTHON_EXE%" -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload"

:: 5. Start Frontend Server
echo.
echo ===============================================================================
echo [2/3] Starting React Vite SOC Dashboard...
echo ===============================================================================
start "SentinelAI Frontend [Port 5173]" cmd /k "title SentinelAI Frontend && cd /d "%~dp0frontend" && npm run dev -- --host 127.0.0.1 --port 5173"

:: 6. Wait for initialization & Launch Browser
echo.
echo ===============================================================================
echo [3/3] Initializing components and launching web interface...
echo ===============================================================================
timeout /t 4 /nobreak >nul

echo [*] Opening browser at http://localhost:5173 ...
start http://localhost:5173

echo.
color 0A
echo ===============================================================================
echo             >>> SENTINELAI X IS RUNNING SUCCESSFULLY! <<<
echo ===============================================================================
echo  - Frontend Dashboard   : http://localhost:5173
echo  - Backend API Engine   : http://localhost:8000
echo  - Swagger API Docs     : http://localhost:8000/api/docs
echo  - Cyber Range Simulator: Click '⚡ Cyber Range Simulator' on the sidebar
echo  - SOAR Active Defense  : Click '🛡️ SOAR & Active Defense' on the sidebar
echo  - MITRE ATT&CK Matrix  : Click '🗺️ MITRE ATT&CK Matrix' on the sidebar
echo ===============================================================================
echo.
echo [!] Keep this window open. When finished, press any key to shutdown all servers.
pause >nul

echo.
echo [*] Stopping SentinelAI servers...
taskkill /FI "WINDOWTITLE eq SentinelAI Backend*" /T /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq SentinelAI Frontend*" /T /F >nul 2>&1
echo [OK] All servers shut down cleanly.
timeout /t 2 /nobreak >nul
exit /b 0