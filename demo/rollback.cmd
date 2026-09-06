@echo off
REM The rollback demo. Four beats, in order:
REM   1. a normal release, which issues a signed certificate
REM   2. a rollback of that artifact weeks later, with nothing to show for it
REM   3. the same rollback with the original certificate presented
REM   4. a rollback of a digest nobody ever built, certificate and all
setlocal
cd /d "%~dp0\.."

set MASKEDRUNNER_SIGNING_KEY=1111111111111111111111111111111111111111111111111111111111111111
set BIN=target\release\maskedrunner.exe
set CERT=%TEMP%\maskedrunner-release.cert.json

if not exist "%BIN%" (
  echo Building...
  cargo build --release -p maskedrunner-cli || exit /b 1
)

echo(
echo ============================================================
echo   1  The original release, three weeks ago
echo ============================================================
"%BIN%" verify --observation fixtures\case1.json --certificate "%CERT%"
pause

echo(
echo ============================================================
echo   2  Production is broken. Roll back to that artifact.
echo      No evidence presented.
echo ============================================================
"%BIN%" verify --observation fixtures\case4-rollback.json
echo(
echo   Rejected. Nothing in THIS run built that digest, and the
echo   verifier will not take the runner's word for it.
pause

echo(
echo ============================================================
echo   3  Same rollback. Now present the original certificate.
echo ============================================================
"%BIN%" verify --observation fixtures\case4-rollback.json --evidence "%CERT%"
echo(
echo   Accepted. The signature proves that digest already passed
echo   build and test under this same workflow.
pause

echo(
echo ============================================================
echo   4  The attack: roll back a digest that never existed,
echo      holding a real certificate.
echo ============================================================
"%BIN%" verify --observation fixtures\case5-rollback-forged.json --evidence "%CERT%"
echo(
echo   Rejected. A certificate is evidence for the digest it names
echo   and nothing else. It is not a skip button.
echo(
endlocal
