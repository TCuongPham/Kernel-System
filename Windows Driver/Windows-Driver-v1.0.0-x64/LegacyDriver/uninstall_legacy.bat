@echo off
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] Vui long chay script nay duoi quyen Administrator!
    pause
    exit /b 1
)

echo [*] Dang dung LegacyDriver...
sc stop LegacyDriver
echo [*] Dang go bo LegacyDriver...
sc delete LegacyDriver
echo.
echo [+] Da go bo LegacyDriver thanh cong!
pause
