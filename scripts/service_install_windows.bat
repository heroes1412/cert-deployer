@echo off
setlocal enabledelayedexpansion
echo ===================================================
echo Windows Native Service Installer for Cert Vault Server (sc.exe)
echo ===================================================

:: Check for Administrator privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Please run this batch file as Administrator!
    pause
    exit /b 1
)

set SCRIPT_DIR=%~dp0
for %%I in ("%SCRIPT_DIR%..") do set ROOT_DIR=%%~fI
set SERVER_BIN=%ROOT_DIR%\build\windows\cert-server.exe

if not exist "%SERVER_BIN%" (
    echo [ERROR] Server binary not found at %SERVER_BIN%. Please run build.bat first!
    pause
    exit /b 1
)

echo [1/2] Registering CertVaultServer Windows Service natively via sc.exe...
sc query CertVaultServer >nul 2>&1
if %errorlevel% eq 0 (
    echo [INFO] Service CertVaultServer already exists. Stopping and re-creating...
    sc stop CertVaultServer >nul 2>&1
    sc delete CertVaultServer >nul 2>&1
    timeout /t 2 /nobreak >nul
)

sc create CertVaultServer binPath= "\"%SERVER_BIN%\"" start= auto displayname= "Cert Vault Server Service"
sc description CertVaultServer "Centralized Certificate Management System Server"
sc start CertVaultServer

echo.
echo ===================================================
echo SUCCESS: CertVaultServer Windows Service Registered!
echo Management Commands:
echo   - Start:   sc start CertVaultServer
echo   - Stop:    sc stop CertVaultServer
echo   - Status:  sc query CertVaultServer
echo   - Remove:  sc delete CertVaultServer
echo ===================================================
pause
