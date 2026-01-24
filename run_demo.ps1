Write-Host "Starting SecureEV-OTA Demo..."
Write-Host "--------------------------------"
$VENV_PYTHON = ".\.venv\Scripts\python.exe"

Write-Host "1. Launching Director Service (Port 8000)..."
Start-Process $VENV_PYTHON -ArgumentList "-m uvicorn src.services.director:app --port 8000" -WindowStyle Minimized

Write-Host "2. Launching Image Repository (Port 8001)..."
Start-Process $VENV_PYTHON -ArgumentList "-m uvicorn src.services.image_repo:app --port 8001" -WindowStyle Minimized

Write-Host "Waiting 5 seconds for services to initialize..."
Start-Sleep -Seconds 5

Write-Host "3. Launching Fleet Simulation..."
& $VENV_PYTHON simulation.py
