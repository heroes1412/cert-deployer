@echo off
set PATH=C:\Program Files\Go\bin;%PATH%
echo ===================================================
echo Building Cert Deployer Server and Client (Windows ^& Linux)
echo ===================================================

if not exist "build" mkdir build
if not exist "build\windows" mkdir build\windows
if not exist "build\linux" mkdir build\linux

echo.
echo [1/4] Building Server for Windows (build\windows\cert-deployer-server.exe)...
cd server
set GOOS=windows
set GOARCH=amd64
go build -o ..\build\windows\cert-deployer-server.exe .
if %errorlevel% neq 0 (
    echo [ERROR] Failed to build server for Windows!
    cd ..
    exit /b %errorlevel%
)

echo [2/4] Building Server for Linux (build\linux\cert-deployer-server)...
set GOOS=linux
set GOARCH=amd64
go build -o ..\build\linux\cert-deployer-server .
if %errorlevel% neq 0 (
    echo [ERROR] Failed to build server for Linux!
    cd ..
    exit /b %errorlevel%
)
cd ..

echo.
echo [3/4] Building Client Agent for Windows (build\windows\cert-deployer-agent.exe)...
cd client
set GOOS=windows
set GOARCH=amd64
go build -o ..\build\windows\cert-deployer-agent.exe .
if %errorlevel% neq 0 (
    echo [ERROR] Failed to build client for Windows!
    cd ..
    exit /b %errorlevel%
)

echo [4/4] Building Client Agent for Linux (build\linux\cert-deployer-agent)...
set GOOS=linux
set GOARCH=amd64
go build -o ..\build\linux\cert-deployer-agent .
if %errorlevel% neq 0 (
    echo [ERROR] Failed to build client for Linux!
    cd ..
    exit /b %errorlevel%
)
cd ..

echo.
echo ===================================================
echo SUCCESS: All binaries successfully built!
echo Output Directory:
echo   - Windows: build\windows\cert-deployer-server.exe, build\windows\cert-deployer-agent.exe
echo   - Linux:   build\linux\cert-deployer-server, build\linux\cert-deployer-agent
echo ===================================================
