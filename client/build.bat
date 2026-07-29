@echo off
set PATH=C:\Program Files\Go\bin;%PATH%
echo Building Client Agent binaries (Windows ^& Linux)...
set GOOS=windows
set GOARCH=amd64
go build -o cert-agent.exe main.go

set GOOS=linux
set GOARCH=amd64
go build -o cert-agent main.go

echo Client Agent build complete: cert-agent.exe (Windows), cert-agent (Linux)
