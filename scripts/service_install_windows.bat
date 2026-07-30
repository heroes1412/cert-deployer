@echo off
setlocal enabledelayedexpansion
echo ===================================================
echo Windows Native Service Installer for Cert Server (sc.exe)
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

echo [1/2] Registering CertServer Windows Service natively via sc.exe...
sc query CertServer >nul 2>&1
if %errorlevel% equ 0 (
    echo [INFO] Service CertServer already exists. Stopping and re-creating...
    sc stop CertServer >nul 2>&1
    sc delete CertServer >nul 2>&1
    timeout /t 2 /nobreak >nul
)

sc create CertServer binPath= "\"%SERVER_BIN%\"" start= auto displayname= "Cert Server Service"
sc description CertServer "Cert Server Component of Cert Deployer Solution"
sc start CertServer

echo.
echo ===================================================
echo SUCCESS: CertServer Windows Service Registered!
echo Management Commands:
echo   - Start:   sc start CertServer
echo   - Stop:    sc stop CertServer
echo   - Status:  sc query CertServer
echo   - Remove:  sc delete CertServer
echo ===================================================
pause
