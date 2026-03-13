# SecureEV-OTA Demo Launcher
Write-Host "Starting SecureEV-OTA Demo..." -ForegroundColor Cyan
Write-Host "--------------------------------"

# Load Python Discovery Utility
. .\get_python.ps1
$VENV_PYTHON = Get-PythonPath
Write-Host "Using Python: $VENV_PYTHON" -ForegroundColor Gray

Write-Host "1. Launching Director Service (Port 8000)..." -ForegroundColor Green
Start-Process $VENV_PYTHON -ArgumentList "-m uvicorn src.server.director:app --port 8000" -WindowStyle Minimized

Write-Host "2. Launching Image Repository (Port 8001)..." -ForegroundColor Green
Start-Process $VENV_PYTHON -ArgumentList "-m uvicorn src.server.image_repo:app --port 8001" -WindowStyle Minimized

Write-Host "Waiting 5 seconds for services to initialize..." -ForegroundColor Yellow
Start-Sleep -Seconds 5

Write-Host "3. Launching Fleet Simulation..." -ForegroundColor Cyan
& $VENV_PYTHON simulation.py
