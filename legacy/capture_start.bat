@echo off
setlocal

rem <<< USTAW TUTAJ NUMER INTERFEJSU Z "dumpcap -D" >>>
set "IFACE=8"

rem (opcjonalnie) pełna ścieżka do dumpcap, jeśli nie masz w PATH:
set "DUMPCAP=C:\Program Files\Wireshark\dumpcap.exe"
if not exist "%DUMPCAP%" set "DUMPCAP=dumpcap.exe"

rem katalog wyjściowy względem tego pliku
set "OUTDIR=%~dp0..\pcap"
if not exist "%OUTDIR%" mkdir "%OUTDIR%"

echo [i] Start capture on IFACE=%IFACE% -> %OUTDIR%
"%DUMPCAP%" -i %IFACE% -f "tcp port 502" ^
  -b duration:600 -b files:20 ^
  -w "%OUTDIR%\cap-%%Y%%m%%d-%%H%%M%%S.pcapng" -q
