@echo off
REM Create Desktop Shortcut for PCAP Analyzer
REM This script creates a Windows shortcut on your Desktop

setlocal enabledelayedexpansion

echo.
echo ====================================================
echo   Create Desktop Shortcut
echo ====================================================
echo.

REM Get the current directory
set ANALYZER_DIR=%CD%
set QUICK_START=%ANALYZER_DIR%\run.bat
set DESKTOP=%USERPROFILE%\Desktop

REM Check if run.bat exists
if not exist "%QUICK_START%" (
    echo ERROR: run.bat not found in:
    echo %ANALYZER_DIR%
    echo.
    pause
    exit /b 1
)

REM Create VBS script to create shortcut
set TEMP_VBS=%TEMP%\create_shortcut.vbs

(
    echo Set oWS = WScript.CreateObject("WScript.Shell"^)
    echo sLinkFile = "%DESKTOP%\PCAP Analyzer.lnk"
    echo Set oLink = oWS.CreateShortcut(sLinkFile^)
    echo oLink.TargetPath = "%QUICK_START%"
    echo oLink.WorkingDirectory = "%ANALYZER_DIR%"
    echo oLink.Description = "PCAP Analyzer - Double-click to analyze PCAPs"
    echo oLink.IconLocation = "%SystemRoot%\System32\shell32.dll,16"
    echo oLink.Save
) > "%TEMP_VBS%"

REM Run the VBS script
cscript "%TEMP_VBS%" >nul 2>&1

if %errorlevel% equ 0 (
    echo.
    echo SUCCESS!
    echo.
    echo Shortcut created on Desktop:
    echo "%DESKTOP%\PCAP Analyzer.lnk"
    echo.
    echo You can now:
    echo   1. Double-click the Desktop shortcut to analyze PCAPs
    echo   2. Copy PCAP files to input/ folder
    echo   3. Run analysis with one click
    echo.
) else (
    echo.
    echo ERROR: Could not create shortcut
    echo.
    echo Manual method:
    echo   1. Right-click run.bat
    echo   2. Select "Send to" ^> "Desktop (create shortcut)"
    echo   3. Done!
    echo.
)

REM Clean up
del "%TEMP_VBS%" >nul 2>&1

pause
