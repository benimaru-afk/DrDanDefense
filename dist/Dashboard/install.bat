@echo off
setlocal

:: ── Resolve the folder this .bat lives in (no trailing backslash) ────────────
set "APP_DIR=%~dp0"
set "APP_DIR=%APP_DIR:~0,-1%"

set "EXE=%APP_DIR%\Dashboard.exe"
set "ICO=%APP_DIR%\DrDan.ico"

:: ── Sanity check ─────────────────────────────────────────────────────────────
if not exist "%EXE%" (
    echo [ERROR] Dashboard.exe not found in %APP_DIR%
    echo         Make sure you run install.bat from inside the Dashboard folder.
    pause
    exit /b 1
)

:: ── Create shortcut via PowerShell ───────────────────────────────────────────
:: [Environment]::GetFolderPath resolves the real Desktop even when
:: OneDrive redirects it away from %USERPROFILE%\Desktop
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "$desktop  = [Environment]::GetFolderPath('Desktop');" ^
    "$shortcut = Join-Path $desktop 'Advanced Antivirus Suite.lnk';" ^
    "$ws = New-Object -ComObject WScript.Shell;" ^
    "$s  = $ws.CreateShortcut($shortcut);" ^
    "$s.TargetPath       = '%EXE%';" ^
    "$s.WorkingDirectory = '%APP_DIR%';" ^
    "$s.IconLocation     = '%ICO%,0';" ^
    "$s.Description      = 'Advanced Antivirus Suite';" ^
    "$s.Save();" ^
    "Write-Host ('Shortcut created: ' + $shortcut)"

echo.
pause
endlocal
