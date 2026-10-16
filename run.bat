@echo off
setlocal enabledelayedexpansion
title SentinelAI X - Enterprise SOC Copilot Launcher
cd /d "%~dp0"
color 0B

echo ===============================================================================
echo                SENTINELAI X - MCP SECURITY COPILOT v2.0
echo          Enterprise Autonomous SOC Analyst ^& Cyber Range
echo ===============================================================================
echo.

:: ============================================================
:: 1. Locate Python (venv first, then system)
:: ============================================================
set "PYTHON_EXE=%~dp0.venv\Scripts\python.exe"
if not exist "%PYTHON_EXE%" (
    echo [!] Venv python not found. Checking system python...
    for %%P in (python.exe) do set "PYTHON_EXE=%%~$PATH:P"
    if not defined PYTHON_EXE (
        echo [ERROR] Python not found. Please install Python 3.10+
        exit /b 1
    )
)
echo [OK] Python Engine : %PYTHON_EXE%

:: ============================================================
:: 2. Locate Node.js
:: ============================================================
set "NODE_EXE="
for %%N in (node.exe) do set "NODE_EXE=%%~$PATH:N"
if not defined NODE_EXE (
    if exist "C:\Program Files\nodejs\node.exe" set "NODE_EXE=C:\Program Files\nodejs\node.exe"
)
if not defined NODE_EXE (
    if exist "C:\Program Files (x86)\nodejs\node.exe" set "NODE_EXE=C:\Program Files (x86)\nodejs\node.exe"
)
if not defined NODE_EXE (
    echo [ERROR] Node.js not found. Please install Node.js v18+
    exit /b 1
)
echo [OK] Node.js Engine: %NODE_EXE%

:: ============================================================
:: 3. Free ports 8000 and 5173 if busy
:: ============================================================
echo [*] Checking network ports 8000 and 5173...
for /f "tokens=5" %%a in ('netstat -aon 2^>nul ^| findstr ":8000 "') do (
    if "%%a" neq "0" (
        echo [*] Freeing port 8000 ^(PID %%a^)...
        taskkill /F /PID %%a >nul 2>&1
    )
)
for /f "tokens=5" %%a in ('netstat -aon 2^>nul ^| findstr ":5173 "') do (
    if "%%a" neq "0" (
        echo [*] Freeing port 5173 ^(PID %%a^)...
        taskkill /F /PID %%a >nul 2>&1
    )
)

:: ============================================================
:: 4. Zero-Click Autonomous Wazuh VirtualBox VM Boot (Headless)
:: ============================================================
echo.
echo ===============================================================================
echo [1/4] Checking and Booting Wazuh VirtualBox VM (Zero-Click Mode)...
echo ===============================================================================
set "VBOX_MANAGE=C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
set "WAZUH_VM_NAME=Wazuh v4.14.7 OVA"

if exist "%VBOX_MANAGE%" (
    "%VBOX_MANAGE%" list runningvms | findstr /C:"%WAZUH_VM_NAME%" >nul 2>&1
    if errorlevel 1 (
        echo [*] Wazuh VM is offline. Starting "%WAZUH_VM_NAME%" in headless mode...
        echo [*] Booting silently in the background [headless mode]...
        "%VBOX_MANAGE%" startvm "%WAZUH_VM_NAME%" --type headless >nul 2>&1
        echo [OK] Wazuh VM successfully started in background!
    ) else (
        echo [OK] Wazuh VM is ALREADY RUNNING in background.
    )
) else (
    echo [!] VirtualBox not detected at default location. Skipping VM boot.
)

:: ============================================================
:: 5. Start Backend (FastAPI)
:: ============================================================
echo.
echo ===============================================================================
echo [2/4] Starting FastAPI SOC Backend on port 8000...
echo ===============================================================================
set "BACKEND_DIR=%~dp0backend"
set "BACKEND_PYTHON=%PYTHON_EXE%"
start "SentinelAI Backend" cmd /k "title SentinelAI Backend [8000] && cd /d "%BACKEND_DIR%" && set PYTHONPATH=%BACKEND_DIR% && "%BACKEND_PYTHON%" -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload"

:: ============================================================
:: 6. Start Frontend (Vite/React)
:: ============================================================
echo.
echo ===============================================================================
echo [3/4] Starting React Vite SOC Dashboard on port 5173...
echo ===============================================================================
set "FRONTEND_DIR=%~dp0frontend"
start "SentinelAI Frontend" cmd /k "title SentinelAI Frontend [5173] && cd /d "%FRONTEND_DIR%" && npm run dev -- --host 127.0.0.1 --port 5173"

:: ============================================================
:: 7. Wait then open browser
:: ============================================================
echo.
echo ===============================================================================
echo [4/4] Initializing components and launching Web Command Center...
echo ===============================================================================
timeout /t 5 /nobreak >nul

echo [*] Opening browser at http://localhost:5173 ...
start http://localhost:5173

:: ============================================================
:: Done
:: ============================================================
echo.
color 0A
echo ===============================================================================
echo          ^>^>^> SENTINELAI X IS RUNNING SUCCESSFULLY! ^<^<^<
echo ===============================================================================
echo  - Frontend Dashboard   : http://localhost:5173
echo  - Backend API Engine   : http://localhost:8000
echo  - Swagger API Docs     : http://localhost:8000/api/docs
echo  - Wazuh VirtualBox VM  : Running in Background (Headless)
echo  - Cyber Range          : Sidebar - "Cyber Range Simulator"
echo  - SOAR Active Defense  : Sidebar - "SOAR ^& Active Defense"
echo  - MITRE ATT^&CK Matrix  : Sidebar - "MITRE ATT^&CK Matrix"
echo ===============================================================================
echo.
echo [!] All services are running autonomously in separate windows.
echo [!] Close those windows or run stop_wazuh_vm.bat when done.
echo.
exit /b 0
