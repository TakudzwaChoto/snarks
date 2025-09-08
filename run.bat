@echo off
echo Starting LLM Security Application with Docker...
echo.
echo If Docker is not installed, please install Docker Desktop first.
echo.

REM Check if Docker is available
docker --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Docker is not installed or not running.
    echo Please install Docker Desktop from https://www.docker.com/products/docker-desktop
    pause
    exit /b 1
)

REM Build and run the application
echo Building and starting the application...
docker-compose up --build

pause 