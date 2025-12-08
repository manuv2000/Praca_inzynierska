@echo off
setlocal

REM Parametry (opcjonalne): host port unit
set "HOST=%~1"
set "PORT=%~2"
set "UNIT=%~3"

if "%HOST%"=="" set "HOST=127.0.0.1"
if "%PORT%"=="" set "PORT=502"
if "%UNIT%"=="" set "UNIT=1"

echo [info] Using python from PATH...
python --version

echo [info] Running health check: host=%HOST% port=%PORT% unit=%UNIT%
python -c "from injector.health_check import ping_hr0; ping_hr0(host='%HOST%', port=%PORT%, unit=%UNIT%, samples=20)"
exit /b %ERRORLEVEL%
