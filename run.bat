@echo off
setlocal enabledelayedexpansion

cd /d "%~dp0"
set SCRIPT_DIR=%CD%
set INPUT_DIR=%SCRIPT_DIR%\input
set OUTPUT_DIR=%SCRIPT_DIR%\output

cls
echo.
echo ========================================
echo   PCAP Analyzer
echo ========================================
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH.
    echo Install Python 3.7+ from https://www.python.org/downloads/
    echo and check "Add Python to PATH" during installation.
    pause
    exit /b 1
)

if not exist "%INPUT_DIR%" mkdir "%INPUT_DIR%"
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

echo Input:  %INPUT_DIR%
echo Output: %OUTPUT_DIR%
echo.

set COUNT=0
for /r "%INPUT_DIR%" %%F in (*.pcap *.pcapng) do set /a COUNT+=1

if %COUNT% equ 0 (
    echo [WARNING] No PCAP files found in %INPUT_DIR%
    echo Place .pcap or .pcapng files there and run again.
    pause
    exit /b 1
)

echo [FOUND] %COUNT% PCAP file(s). Starting analysis...
echo.

python run_analysis.py

if errorlevel 1 (
    echo.
    echo [ERROR] Analysis failed. Check the logs folder for details.
    pause
    exit /b 1
)

echo.
echo ========================================
echo   Analysis Complete
echo ========================================
echo Reports saved to: %OUTPUT_DIR%
echo.

set /p OPEN_FOLDER="Open output folder now? (Y/N): "
if /i "%OPEN_FOLDER%"=="Y" start explorer "%OUTPUT_DIR%"

pause
exit /b 0
