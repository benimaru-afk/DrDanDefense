@echo off
setlocal

:: ── Resolve the folder this .bat lives in (no trailing backslash) ────────────
set "APP_DIR=%~dp0"
set "APP_DIR=%APP_DIR:~0,-1%"

set "EXE=%APP_DIR%\Dashboard.exe"
set "ICO=%APP_DIR%\DrDan.ico"
set "SHORTCUT=%USERPROFILE%\Desktop\Advanced Antivirus Suite.lnk"

:: ── Sanity check ─────────────────────────────────────────────────────────────
if not exist "%EXE%" (
    echo [ERROR] Dashboard.exe not found in %APP_DIR%
    echo         Make sure you run install.bat from inside the Dashboard folder.
    pause
    exit /b 1
)

:: ── Create shortcut via PowerShell ───────────────────────────────────────────
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "$ws = New-Object -ComObject WScript.Shell;" ^
    "$s  = $ws.CreateShortcut('%SHORTCUT%');" ^
    "$s.TargetPath      = '%EXE%';" ^
    "$s.WorkingDirectory = '%APP_DIR%';" ^
    "$s.IconLocation    = '%ICO%,0';" ^
    "$s.Description     = 'Advanced Antivirus Suite';" ^
    "$s.Save()"

if exist "%SHORTCUT%" (
    echo.
    echo  Desktop shortcut created successfully.
    echo  You can now launch the app from your Desktop.
    echo.
) else (
    echo.
    echo  [WARNING] Shortcut may not have been created. Check PowerShell permissions.
    echo.
)

pause
endlocal
