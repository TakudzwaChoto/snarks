@echo off
echo Installing Python using Chocolatey...
echo.

REM Check if Chocolatey is available
choco --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Chocolatey not found. Installing Chocolatey first...
    echo Please run PowerShell as Administrator and execute:
    echo Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    echo.
    echo Then run this script again.
    pause
    exit /b 1
)

REM Install Python
echo Installing Python 3.11...
choco install python311 -y

echo.
echo Python installation complete!
echo Please restart your terminal and try running: python app.py
pause 