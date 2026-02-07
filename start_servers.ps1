# SecureEV-OTA Backend Startup Script
# Starts both Director and Image Repository servers

Write-Host "Starting SecureEV-OTA Backend Services..." -ForegroundColor Cyan

# Create storage directory if it doesn't exist
New-Item -ItemType Directory -Force -Path "repo_storage/images" | Out-Null

# Start Director (Port 8000)
Write-Host "Starting Director Repository on port 8000..." -ForegroundColor Green
$director = Start-Process -PassThru -NoNewWindow powershell -ArgumentList "-Command", "uvicorn src.server.director:app --host 0.0.0.0 --port 8000"

# Start Image Repo (Port 8001)
Write-Host "Starting Image Repository on port 8001..." -ForegroundColor Green
$imageRepo = Start-Process -PassThru -NoNewWindow powershell -ArgumentList "-Command", "uvicorn src.server.image_repo:app --host 0.0.0.0 --port 8001"

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
