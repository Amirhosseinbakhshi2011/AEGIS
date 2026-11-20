$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "== AEGIS installer (PowerShell) =="

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    throw "Python was not found on PATH."
}

$version = & python -c "import sys; print('%d.%d' % sys.version_info[:2])"
if ([version]$version -lt [version]"3.12") {
    throw "Python 3.12 or newer is required; found $version."
}
Write-Host "Python $version"

$venvPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $venvPython)) {
    Write-Host "Creating virtual environment..."
    & python -m venv .venv
    if ($LASTEXITCODE -ne 0) { throw "Could not create virtual environment." }
}

Write-Host "Upgrading pip..."
& $venvPython -m pip install --upgrade pip

Write-Host "Installing AEGIS and development dependencies..."
& $venvPython -m pip install -e ".[dev]"
if ($LASTEXITCODE -ne 0) { throw "Installation failed." }

if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host "Created .env from .env.example"
} else {
    Write-Host ".env already exists; leaving it unchanged."
}

Write-Host ""
Write-Host "Done. Next steps:"
Write-Host "  .\.venv\Scripts\Activate.ps1"
Write-Host "  aegis --help"
