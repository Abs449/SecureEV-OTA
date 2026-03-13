# SecureEV-OTA: Test Runner Utility
Write-Host "Running SecureEV-OTA Tests..." -ForegroundColor Cyan

# Load Python Discovery Utility
. .\get_python.ps1
$VENV_PYTHON = Get-PythonPath
Write-Host "Using Python: $VENV_PYTHON" -ForegroundColor Gray

# Run pytest with all arguments passed to this script
& $VENV_PYTHON -m pytest $args
