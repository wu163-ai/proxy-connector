@echo off
setlocal
cd /d "%~dp0"
set "LAUNCH="
where pyw >nul 2>nul && set "LAUNCH=pyw -3.14"
if not defined LAUNCH if exist "%LOCALAPPDATA%\Programs\Python\Python314\pythonw.exe" set "LAUNCH=%LOCALAPPDATA%\Programs\Python\Python314\pythonw.exe"
if not defined LAUNCH (
    echo [!] pythonw.exe not found.
    echo     Install Python 3.10+ with "tcl/tk and IDLE" checked.
    pause
    exit /b 1
)
start "proxy-connector" %LAUNCH% "%~dp0socks5_connector.py" %*
