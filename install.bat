@echo off
setlocal
cd /d "%~dp0"

echo == AEGIS installer (Windows CMD) ==

where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python was not found on PATH.
    exit /b 1
)

python -c "import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)"
if errorlevel 1 (
    echo [ERROR] Python 3.12 or newer is required.
    exit /b 1
)
for /f "tokens=2" %%v in ('python --version 2^>^&1') do set PYVER=%%v
echo Python %PYVER%

if not exist ".venv\Scripts\python.exe" (
    echo Creating virtual environment...
    python -m venv .venv
    if errorlevel 1 (
        echo [ERROR] Could not create virtual environment.
        exit /b 1
    )
)

echo Upgrading pip...
".venv\Scripts\python.exe" -m pip install --upgrade pip

echo Installing AEGIS and development dependencies...
".venv\Scripts\python.exe" -m pip install -e ".[dev]"
if errorlevel 1 (
    echo [ERROR] Installation failed.
    exit /b 1
)

if not exist ".env" (
    copy /y ".env.example" ".env" >nul
    echo Created .env from .env.example
) else (
    echo .env already exists; leaving it unchanged.
)

echo.
echo Done. Next steps:
echo   .venv\Scripts\activate.bat
echo   aegis --help
endlocal
