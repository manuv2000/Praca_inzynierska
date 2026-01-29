import json
import shutil
import subprocess
from pathlib import Path
from typing import Optional

TSHARK_FIXED_PATH = r"C:\Program Files\Wireshark\tshark.exe"

def _get_tshark_exe() -> str:
    exe = shutil.which("tshark")
    return exe if exe else TSHARK_FIXED_PATH

def pcap_to_json(pcap_path: Path, out_path: Optional[Path] = None) -> str:
    """
    Zwraca JSON jako string (albo zapisuje do pliku, jeśli out_path podane).
    """
    tshark = _get_tshark_exe()
    cmd = [
        tshark,
        "-r", str(pcap_path),
        "-T", "json",
        "-j", "frame ip tcp modbus",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"tshark failed: {proc.stderr.strip()}")

    if out_path:
        out_path.write_text(proc.stdout, encoding="utf-8")
        return str(out_path)

    # walidacja: czy to jest JSON
    json.loads(proc.stdout)
    return proc.stdout
