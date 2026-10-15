@echo off
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] Vui long chay script nay duoi quyen Administrator!
    pause
    exit /b 1
)

cd /d "%~dp0"
echo [*] Dang cai dat MinifilterDriver qua INF...
rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 132 .\MinifilterDriver.inf
echo [*] Dang nap MinifilterDriver vao Filter Manager...
fltmc load MinifilterDriver
echo.
echo [+] Hoan tat! Ban co the chay MonitorClient.exe de theo doi log.
pause
