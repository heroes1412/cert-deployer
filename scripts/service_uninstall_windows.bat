@echo off
setlocal enabledelayedexpansion
echo ===================================================
echo Windows Native Service Uninstaller for Cert Server
echo ===================================================

:: Check for Administrator privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Please run this batch file as Administrator!
    pause
    exit /b 1
)

echo [1/2] Checking CertServer Windows Service...
sc query CertServer >nul 2>&1
if %errorlevel% equ 0 (
    echo [INFO] Stopping CertServer service...
    sc stop CertServer >nul 2>&1
    timeout /t 2 /nobreak >nul
    echo [INFO] Removing CertServer service...
    sc delete CertServer >nul 2>&1
    echo [SUCCESS] CertServer service removed successfully.
) else (
    sc query CertDeployerServer >nul 2>&1
    if !errorlevel! equ 0 (
        echo [INFO] Stopping CertDeployerServer service...
        sc stop CertDeployerServer >nul 2>&1
        timeout /t 2 /nobreak >nul
        echo [INFO] Removing CertDeployerServer service...
        sc delete CertDeployerServer >nul 2>&1
        echo [SUCCESS] CertDeployerServer service removed successfully.
    ) else (
        echo [INFO] Service is not installed. Nothing to remove.
    )
)

echo.
echo ===================================================
echo SUCCESS: Windows Service Uninstalled!
echo ===================================================
pause
