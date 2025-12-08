@echo off
taskkill /IM dumpcap.exe /F >nul 2>&1
if %ERRORLEVEL% EQU 0 (
  echo [i] dumpcap stopped
) else (
  echo [!] dumpcap not running
)
