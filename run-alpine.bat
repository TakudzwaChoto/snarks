@echo off
echo Starting LLM Security Application with Alpine Python...
echo.

REM Check if Docker is available
docker --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Docker is not installed or not running.
    echo Please install Docker Desktop from https://www.docker.com/products/docker-desktop
    pause
    exit /b 1
)

REM Build and run with Alpine Dockerfile
echo Building and starting the application...
docker build -f Dockerfile.alpine -t llm-security-alpine .
docker run -p 5000:5000 llm-security-alpine

pause 