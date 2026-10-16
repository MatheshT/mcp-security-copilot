@echo off
setlocal enabledelayedexpansion
title SentinelAI X - Wazuh VM Controller
color 0B

echo ===============================================================================
echo               WAZUH VIRTUALBOX AUTONOMOUS VM CONTROLLER
echo ===============================================================================
echo.

set "VBOX_MANAGE=C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
if not exist "%VBOX_MANAGE%" (
    echo [ERROR] VirtualBox not found at "%VBOX_MANAGE%"
    pause
    exit /b 1
)

set "VM_NAME=Wazuh v4.14.7 OVA"

:: Check current state
echo [*] Checking state for VM: "%VM_NAME%"...
"%VBOX_MANAGE%" list runningvms | findstr /C:"%VM_NAME%" >nul 2>&1
if %errorlevel% equ 0 (
    color 0A
    echo [OK] Wazuh VM is ALREADY RUNNING in VirtualBox!
    echo.
    echo   - Wazuh Dashboard : https://192.168.56.101
    echo   - Wazuh API       : https://192.168.56.101:55000
    echo   - Credentials     : admin / admin (or wazuh-wui / wazuh-wui)
    echo.
    pause
    exit /b 0
)

echo [*] Starting "%VM_NAME%" in headless background mode...
echo [*] No VirtualBox window will pop up - it will run smoothly in background.
echo.

"%VBOX_MANAGE%" startvm "%VM_NAME%" --type headless

if %errorlevel% neq 0 (
    echo [!] Headless start failed, trying regular GUI start...
    "%VBOX_MANAGE%" startvm "%VM_NAME%"
)

if %errorlevel% equ 0 (
    color 0A
    echo.
    echo ===============================================================================
    echo [SUCCESS] Wazuh VM is booting up in the background!
    echo ===============================================================================
    echo [*] Please allow 45-60 seconds for OpenSearch and Wazuh Manager to initialize.
    echo   - Wazuh Dashboard : https://192.168.56.101
    echo   - Wazuh API       : https://192.168.56.101:55000
    echo ===============================================================================
) else (
    color 0C
    echo [ERROR] Failed to start VirtualBox VM "%VM_NAME%".
)

echo.
echo Press any key to close this window...
pause >nul
