@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if errorlevel 1 (
    echo [!] Python not found.
    pause
    exit /b 1
)
echo Building dist\proxy-connector.exe ...
py -3.14 -m PyInstaller --noconfirm --clean -F -w -n proxy-connector ^
    --collect-submodules connector ^
    socks5_connector.py
if errorlevel 1 (
    echo.
    echo [!] Build failed. Run "py -3.14 -m pip install pyinstaller" first.
    pause
    exit /b 1
)
echo.
echo Done: dist\proxy-connector.exe
echo Put the exe next to bin\ and sing-box\ so it can find the kernel.
pause
