@echo off
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] Vui long chay script nay duoi quyen Administrator!
    pause
    exit /b 1
)

cd /d "%~dp0"
echo [*] Dang dang ky LegacyDriver service...
sc create LegacyDriver binPath= "%~dp0LegacyDriver.sys" type= kernel
echo [*] Dang khoi dong LegacyDriver...
sc start LegacyDriver
echo.
echo [+] Hoan tat! Ban co the chay Client.exe de kiem tra.
pause
