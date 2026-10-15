@echo off
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] Vui long chay script nay duoi quyen Administrator!
    pause
    exit /b 1
)

echo [*] Dang dung MinifilterDriver...
fltmc unload MinifilterDriver
echo.
echo [+] Da dung MinifilterDriver thanh cong!
pause
