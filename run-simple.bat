@echo off
echo Starting LLM Security Application with Simple Docker Setup...
echo.

REM Check if Docker is available
docker --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Docker is not installed or not running.
    echo Please install Docker Desktop from https://www.docker.com/products/docker-desktop
    pause
    exit /b 1
)

REM Build and run with simple Dockerfile
echo Building and starting the application...
docker build -f Dockerfile.simple -t llm-security-simple .
docker run -p 5000:5000 llm-security-simple

pause 