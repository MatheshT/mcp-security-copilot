@echo off
setlocal enabledelayedexpansion
title SentinelAI X - Stop Wazuh VM
color 0E

echo ===============================================================================
echo               WAZUH VIRTUALBOX VM SAFE SHUTDOWN CONTROLLER
echo ===============================================================================
echo.

set "VBOX_MANAGE=C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
set "VM_NAME=Wazuh v4.14.7 OVA"

if not exist "%VBOX_MANAGE%" (
    echo [ERROR] VirtualBox not found.
    pause
    exit /b 1
)

echo [*] Checking if "%VM_NAME%" is currently running...
"%VBOX_MANAGE%" list runningvms | findstr /C:"%VM_NAME%" >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Wazuh VM is already stopped/powered off.
    timeout /t 3 >nul
    exit /b 0
)

echo [*] Saving VM state safely (prevents database index corruption)...
"%VBOX_MANAGE%" controlvm "%VM_NAME%" savestate

if %errorlevel% equ 0 (
    color 0A
    echo [OK] Wazuh VM state saved successfully!
) else (
    echo [!] Save state failed, sending ACPI power button...
    "%VBOX_MANAGE%" controlvm "%VM_NAME%" acpipowerbutton
)

echo.
timeout /t 3 >nul
exit /b 0
