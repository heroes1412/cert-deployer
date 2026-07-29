@echo off
setlocal enabledelayedexpansion
echo ===================================================
echo Windows Service Installer for Cert Vault Server (NSSM)
echo ===================================================

:: Check for Administrator privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Please run this batch file as Administrator!
    pause
    exit /b 1
)

set SCRIPT_DIR=%~dp0
set ROOT_DIR=%SCRIPT_DIR%..
set SERVER_BIN=%ROOT_DIR%\build\windows\cert-server.exe
set WORK_DIR=%ROOT_DIR%\build\windows

if not exist "%SERVER_BIN%" (
    echo [ERROR] Server binary not found at %SERVER_BIN%. Please run build.bat first!
    pause
    exit /b 1
)

:: Check if NSSM is available in PATH or current dir
where nssm >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo [INFO] NSSM (Non-Sucking Service Manager) is recommended to manage Windows Services.
    echo If NSSM is installed, add it to PATH or place nssm.exe in this folder.
    echo.
    echo Attempting Windows Service registration using NSSM...
)

nssm status CertVaultServer >nul 2>&1
if %errorlevel% eq 0 (
    echo [INFO] Service CertVaultServer already exists. Stopping and updating...
    nssm stop CertVaultServer
) else (
    echo [INFO] Registering CertVaultServer Windows Service via NSSM...
    nssm install CertVaultServer "%SERVER_BIN%"
)

nssm set CertVaultServer AppDirectory "%WORK_DIR%"
nssm set CertVaultServer DisplayName "Cert Vault Server Service"
nssm set CertVaultServer Description "Centralized Certificate Management System Server"
nssm set CertVaultServer Start SERVICE_AUTO_START
nssm set CertVaultServer AppRotateFiles 1
nssm start CertVaultServer

echo.
echo ===================================================
echo SUCCESS: CertVaultServer Windows Service Registered!
echo Status: nssm status CertVaultServer
echo Start:  nssm start CertVaultServer
echo Stop:   nssm stop CertVaultServer
echo ===================================================
pause
