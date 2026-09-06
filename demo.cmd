@echo off
REM MaskedRunner demo launcher: builds if needed, starts the API + UI,
REM opens the browser, and drops you into a CLI window with the `mr` alias.
setlocal
cd /d "%~dp0"

echo(
echo   MaskedRunner demo launcher
echo   ==========================

REM Build the two binaries only if they are missing (fast to skip on demo day).
if not exist "target\release\maskedrunner.exe" goto build
if not exist "target\release\maskedrunner-api.exe" goto build
goto run

:build
echo   Building release binaries (first run only)...
cargo build --release -p maskedrunner-cli -p maskedrunner-api
if errorlevel 1 (
  echo   BUILD FAILED. Fix errors above and re-run.
  pause
  exit /b 1
)

:run
echo   Starting the server window...
start "MaskedRunner server" cmd /k "target\release\maskedrunner-api.exe"

echo   Waiting for the server to come up...
powershell -NoProfile -Command "for($i=0;$i -lt 20;$i++){try{if((Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8787/api/spec -TimeoutSec 1).StatusCode -eq 200){exit 0}}catch{}; Start-Sleep -Milliseconds 300}; exit 1"

echo   Opening the UI in your browser...
start "" "http://localhost:8787"

echo   Opening a CLI window (use: mr scenario, mr verify --observation fixtures\case2.json)...
start "MaskedRunner CLI" cmd /k "doskey mr=target\release\maskedrunner.exe $* && echo Ready. Try:  mr scenario"

echo(
echo   Done. Three windows are open: server, browser (UI), and CLI.
echo   To stop: close the server window (or press Ctrl+C in it).
echo(
endlocal
