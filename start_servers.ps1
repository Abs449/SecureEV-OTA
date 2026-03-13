# SecureEV-OTA Backend Startup Script
# Starts both Director and Image Repository servers
Write-Host "Starting SecureEV-OTA Backend Services..." -ForegroundColor Cyan

# Load Python Discovery Utility
. .\get_python.ps1
$VENV_PYTHON = Get-PythonPath
Write-Host "Using Python: $VENV_PYTHON" -ForegroundColor Gray

# Create storage directory if it doesn't exist
New-Item -ItemType Directory -Force -Path "repo_storage/images" | Out-Null

# Start Director (Port 8000) with concurrency limits
Write-Host "Starting Director Repository on port 8000..." -ForegroundColor Green
$director = Start-Process -PassThru -NoNewWindow $VENV_PYTHON -ArgumentList "-m uvicorn src.server.director:app --host 0.0.0.0 --port 8000 --limit-concurrency 100 --limit-max-requests 1000"

# Start Image Repo (Port 8001) with concurrency limits
Write-Host "Starting Image Repository on port 8001..." -ForegroundColor Green
$imageRepo = Start-Process -PassThru -NoNewWindow $VENV_PYTHON -ArgumentList "-m uvicorn src.server.image_repo:app --host 0.0.0.0 --port 8001 --limit-concurrency 100 --limit-max-requests 1000"

Start-Sleep -Seconds 2

Write-Host ""
Write-Host "Backend Services Running:" -ForegroundColor Yellow
Write-Host "  Director:   http://localhost:8000" -ForegroundColor White
Write-Host "  Image Repo: http://localhost:8001" -ForegroundColor White
Write-Host ""
Write-Host "Press Ctrl+C to stop all services" -ForegroundColor Cyan

# Wait for user to cancel
try {
    Wait-Process -Id $director.Id, $imageRepo.Id
} finally {
    Stop-Process -Id $director.Id -Force -ErrorAction SilentlyContinue
    Stop-Process -Id $imageRepo.Id -Force -ErrorAction SilentlyContinue
    Write-Host "Services stopped." -ForegroundColor Red
}
