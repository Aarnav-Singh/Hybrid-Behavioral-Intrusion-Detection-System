<#
.SYNOPSIS
One-click start script for HB-IDS v2 on Windows.
This script sets up dependencies and runs all services concurrently.
#>

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "    HB-IDS v2: One-Click Start Script" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Cyan

# Ensure cleanup on exit
try {
    Write-Host "1. Validating Docker Engine..." -ForegroundColor Yellow
    docker info > $null 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Docker is not running. Attempting to start Docker Desktop..." -ForegroundColor Red
        Start-Process "C:\Program Files\Docker\Docker\Docker Desktop.exe" -ErrorAction SilentlyContinue
        Write-Host "Waiting 30 seconds for Docker Engine to initialize..." -ForegroundColor Yellow
        Start-Sleep -Seconds 30
    }

    Write-Host "2. Starting PostgreSQL & Redis via Docker..." -ForegroundColor Yellow
    docker-compose up -d postgres redis

    Write-Host "`n3. Setting up Backend..." -ForegroundColor Yellow
    Set-Location backend
    $venvPath = (Get-Item .).FullName + "\.venv"
    $pythonExe = "$venvPath\Scripts\python.exe"
    $uvicornExe = "$venvPath\Scripts\uvicorn.exe"

    if (-Not (Test-Path $venvPath)) {
        Write-Host "Creating Python virtual environment..." -ForegroundColor Gray
        py -3.11 -m venv .venv
    }
    
    # Check if we need to install dependencies (if uvicorn is missing)
    if (-Not (Test-Path $uvicornExe)) {
        Write-Host "Installing missing dependencies..." -ForegroundColor Gray
        & $pythonExe -m pip install --upgrade pip
        & $pythonExe -m pip install poetry
        & $pythonExe -m poetry install
    }

    # Set environment variables
    $env:DATABASE_URL = "postgresql://user:password@localhost:5432/ids"
    $env:REDIS_URL = "redis://localhost:6379/0"
    $env:MODE = "hybrid"
    $env:PYTHONPATH = (Get-Item ..).FullName

    Write-Host "Checking for stale processes on port 8001..." -ForegroundColor Gray
    $staleBackend = Get-NetTCPConnection -LocalPort 8001 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess
    if ($staleBackend) { Stop-Process -Id $staleBackend -Force -ErrorAction SilentlyContinue }

    Write-Host "Starting FastAPI Backend (Port 8001)..." -ForegroundColor Green
    $backendProcess = Start-Process -PassThru -NoNewWindow -FilePath $uvicornExe -ArgumentList "backend.api.main:app", "--reload", "--port", "8001", "--host", "0.0.0.0"
    Set-Location ..

    Write-Host "`n4. Setting up Frontend..." -ForegroundColor Yellow
    Set-Location frontend
    if (-Not (Test-Path "node_modules")) {
        Write-Host "Installing NPM dependencies (this may take a minute)..." -ForegroundColor Gray
        npm install
    }

    Write-Host "Checking for stale processes on port 3000..." -ForegroundColor Gray
    $staleFrontend = Get-NetTCPConnection -LocalPort 3000 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess
    if ($staleFrontend) { Stop-Process -Id $staleFrontend -Force -ErrorAction SilentlyContinue }

    Write-Host "Starting React Frontend (Port 3000)..." -ForegroundColor Green
    $frontendProcess = Start-Process -PassThru -NoNewWindow -FilePath "npm.cmd" -ArgumentList "run", "dev", "--", "--port", "3000"
    Set-Location ..

    Write-Host "`n================================================" -ForegroundColor Cyan
    Write-Host "   Cyber Sentinel v2 is now active!" -ForegroundColor Green
    Write-Host "   -> Dashboard:  http://localhost:3000" -ForegroundColor White
    Write-Host "   -> API Health: http://localhost:8001/api/v1/alerts" -ForegroundColor White
    Write-Host "================================================" -ForegroundColor Cyan
    
    Write-Host "`nKeep this window open to maintain services." -ForegroundColor White
    Write-Host "Press any key to stop all services and exit..." -ForegroundColor Red
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

}
finally {
    Write-Host "`nShutting down services..." -ForegroundColor Yellow
    
    if ($backendProcess) {
        Stop-Process -Id $backendProcess.Id -Force -ErrorAction SilentlyContinue
    }
    if ($frontendProcess) {
        # npm starts sub-processes, so we might need to be more aggressive
        Get-Process -Id $frontendProcess.Id -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    
    # Optionally stop the docker containers
    docker-compose stop postgres redis
    Write-Host "Cleanup complete." -ForegroundColor Green
}
