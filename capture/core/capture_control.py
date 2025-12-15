# capture/core/capture_control.py

import datetime as dt
import os
import subprocess
import shutil
from pathlib import Path
from typing import Optional

BASE_DIR = Path(__file__).resolve().parents[2]
PCAP_DIR = BASE_DIR / "capture" / "pcap"
PID_FILE = BASE_DIR / "capture" / ".capture_pid"

DEFAULT_INTERFACE = "Adapter for loopback traffic capture"

BPF_FILTER = "tcp port 502 or tcp port 1502"

DUMPCAP_FIXED_PATH = r"C:\Program Files\Wireshark\dumpcap.exe"


def _get_dumpcap_exe() -> str:
    env = os.environ.get("DUMPCAP_EXE")
    if env:
        return env
    if shutil.which("dumpcap"):
        return "dumpcap"
    if DUMPCAP_FIXED_PATH and Path(DUMPCAP_FIXED_PATH).exists():
        return DUMPCAP_FIXED_PATH
    raise RuntimeError(
        "Nie znaleziono dumpcap (ani w PATH, ani pod DUMPCAP_FIXED_PATH). "
        "Ustaw DUMPCAP_EXE lub popraw DUMPCAP_FIXED_PATH w capture_control.py."
    )


def start_capture(
    interface: str = DEFAULT_INTERFACE,
    bpf: str = BPF_FILTER,
    ring_size_mb: int = 100,
    label: Optional[str] = None,
) -> Path:
    PCAP_DIR.mkdir(parents=True, exist_ok=True)
    ts = dt.datetime.now().strftime("cap-%Y%m%d-%H%M%S")

    safe_label = ""
    if label:
        import re
        safe_label = "_" + re.sub(r"[^A-Za-z0-9_-]", "_", label)

    pcap_path = PCAP_DIR / f"{ts}{safe_label}.pcapng"
    dumpcap_exe = _get_dumpcap_exe()

    cmd = [
        dumpcap_exe,
        "-i", interface,
        "-f", bpf,
        "-b", f"filesize:{ring_size_mb}",
        "-w", str(pcap_path),
    ]

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=subprocess.DETACHED_PROCESS if os.name == "nt" else 0,
    )

    PID_FILE.write_text(str(proc.pid), encoding="utf-8")
    return pcap_path


def stop_capture() -> Optional[int]:
    if not PID_FILE.exists():
        return None
    pid_str = PID_FILE.read_text(encoding="utf-8").strip()
    if not pid_str:
        return None

    pid = int(pid_str)
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(pid), "/F"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        import signal
        os.kill(pid, signal.SIGTERM)

    PID_FILE.unlink(missing_ok=True)
    return pid
