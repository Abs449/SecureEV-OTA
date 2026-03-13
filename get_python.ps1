# SecureEV-OTA: Python Path Discovery Utility
# Usage: $VENV_PYTHON = . .\get_python.ps1

function Get-PythonPath {
    $venvPaths = @(
        ".\.venv\Scripts\python.exe",
        ".\venv\Scripts\python.exe",
        ".\.venv\bin\python",
        ".\venv\bin\python"
    )
    
    foreach ($path in $venvPaths) {
        $absPath = Join-Path (Get-Location) $path
        if (Test-Path $absPath) { 
            return $absPath 
        }
    }
    
    # Fallback to system python, filtering out potentially problematic MSYS2 interpreters
    $sysPythons = Get-Command python.exe -All -ErrorAction SilentlyContinue | Where-Object { 
        $_.Source -notlike "*msys64*" -and $_.Source -notlike "*mingw*"
    }
    
    if ($sysPythons) {
        return $sysPythons[0].Source
    }
    
    return "python"
}

# If this script is run directly, just output the path
if ($MyInvocation.InvocationName -ne '.') {
    Get-PythonPath
}
