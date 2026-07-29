@echo off
set PATH=C:\Program Files\Go\bin;%PATH%
echo Building Server binaries (Windows ^& Linux)...
set GOOS=windows
set GOARCH=amd64
go build -o cert-server.exe main.go

set GOOS=linux
set GOARCH=amd64
go build -o cert-server main.go

echo Server build complete: cert-server.exe (Windows), cert-server (Linux)
