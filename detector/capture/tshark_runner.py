import subprocess
from pathlib import Path
from typing import Optional

def start_rolling_capture(
    iface: str,
    out_dir: Path,
    bpf_filter: str = "tcp port 502",
    chunk_seconds: int = 5,
    tshark_exe: str = "tshark",
) -> subprocess.Popen:
    """
    Start tshark capture writing PCAPs rotated every chunk_seconds.
    Produces files like capture_00001.pcapng, capture_00002.pcapng, ...
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    out_template = str(out_dir / "capture_%05d.pcapng")

    cmd = [
        tshark_exe,
        "-i", iface,
        "-f", bpf_filter,
        "-b", f"duration:{chunk_seconds}",
        "-w", out_template,
        "-q",
    ]
    # On Windows you may need run as Administrator + Npcap
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
