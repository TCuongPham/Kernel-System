@echo off
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] Vui long chay script nay duoi quyen Administrator!
    pause
    exit /b 1
)

cd /d "%~dp0"
echo [*] Dang cai dat Test Certificate cho LegacyDriver...
certutil -addstore -f "Root" ".\LegacyDriver\LegacyDriver.cer"

echo [*] Dang cai dat Test Certificate cho MinifilterDriver...
certutil -addstore -f "Root" ".\MinifilterDriver\MinifilterDriver.cer"

echo.
echo [+] Cai dat chung chi thanh cong!
pause
