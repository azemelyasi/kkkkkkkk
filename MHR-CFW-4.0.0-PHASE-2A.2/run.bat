@echo off
setlocal
cd /d "%~dp0"
title MHR CFW 3.0.0 - Windows 11
set "PY="
where py >nul 2>&1 && set "PY=py -3"
if "%PY%"=="" where python >nul 2>&1 && set "PY=python"
if "%PY%"=="" (
  echo [ERROR] Python 3.10+ is required. Install Python from https://www.python.org/downloads/windows/
  pause
  exit /b 1
)
if not exist ".venv\Scripts\python.exe" (
  echo [INFO] Creating Python environment...
  %PY% -m venv .venv
  if errorlevel 1 (echo [ERROR] Could not create virtual environment.& pause & exit /b 1)
)
set "VPY=%CD%\.venv\Scripts\python.exe"
"%VPY%" -c "import sys; raise SystemExit(0 if sys.version_info >= (3,10) else 1)"
if errorlevel 1 (echo [ERROR] Python 3.10 or newer is required.& pause & exit /b 1)
echo [INFO] Installing/checking Python dependencies...
"%VPY%" -m pip install --disable-pip-version-check -r requirements.txt
if errorlevel 1 (echo [ERROR] Dependency installation failed.& pause & exit /b 1)
if not exist "config.json" (
  echo [INFO] First run: relay configuration is required.
  "%VPY%" setup.py
  if errorlevel 1 (pause & exit /b 1)
)
"%VPY%" launcher.py
set "RC=%errorlevel%"
if not "%RC%"=="0" pause
exit /b %RC%
