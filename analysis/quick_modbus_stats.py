# analysis/quick_modbus_stats.py

import collections
import math
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Tuple, Dict, Any, Optional

PCAP_EXTENSIONS = (".pcap", ".pcapng")
TSHARK_FIXED_PATH = r"C:\Program Files\Wireshark\tshark.exe"

DEFAULT_DECODE_PORTS = [502, 1502]


def _get_tshark_exe() -> str:
    exe = shutil.which("tshark")
    return exe if exe else TSHARK_FIXED_PATH


def _try_tshark(cmd: List[str]) -> Tuple[int, str, str]:
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, err = proc.communicate()
    return proc.returncode, out, err


def run_tshark(pcap: Path, decode_ports: List[int]) -> Tuple[
    List[float], List[str], List[int], List[int], List[str]
]:
    tshark_exe = _get_tshark_exe()

    # Najczęściej poprawny dissektor dla Modbus/TCP w tshark:
    # - mbtcp (pole modbus.* jest dalej dostępne po dekodowaniu)
    proto_candidates = ["mbtcp", "modbus.tcp", "modbus"]

    base = [
        "-r", str(pcap),
        "-Y", "modbus",   # po poprawnym decode-as pojawi się warstwa modbus
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "modbus.func_code",
        "-e", "modbus.reference_num",
        "-e", "frame.len",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
    ]

    last_err = ""
    out_text = ""

    for proto in proto_candidates:
        cmd = [tshark_exe]
        for p in decode_ports:
            cmd += ["-d", f"tcp.port=={p},{proto}"]
        cmd += base

        code, out, err = _try_tshark(cmd)
        if "isn't valid for layer type" in err or "Valid protocols for layer type" in err:
            last_err = err.strip()
            continue

        out_text = out
        last_err = err.strip()
        break

    if not out_text:
        # tshark może po prostu nie znaleźć modbus (np. pcap bez 1502, albo brak ruchu)
        # ale jeśli decode-as się wywalał, dajemy konkretną podpowiedź:
        if last_err:
            print("tshark stderr:", last_err)
        return [], [], [], [], []

    times: List[float] = []
    func_codes: List[str] = []
    fc6_addrs: List[int] = []
    frame_lens: List[int] = []
    flows: List[str] = []

    for line in out_text.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) < 8:
            continue

        try:
            t = float(parts[0])
        except ValueError:
            continue

        fc = parts[1].strip()
        addr_raw = parts[2].strip()
        len_raw = parts[3].strip()
        ip_src = parts[4].strip()
        ip_dst = parts[5].strip()
        sport = parts[6].strip()
        dport = parts[7].strip()

        addr = -1
        if fc == "6" and addr_raw:
            try:
                addr = int(addr_raw)
            except ValueError:
                addr = -1

        try:
            flen = int(len_raw)
        except ValueError:
            flen = 0

        flow = f"{ip_src}:{sport} -> {ip_dst}:{dport}"

        times.append(t)
        func_codes.append(fc)
        fc6_addrs.append(addr)
        frame_lens.append(flen)
        flows.append(flow)

    return times, func_codes, fc6_addrs, frame_lens, flows


def _entropy_from_counts(counter: collections.Counter) -> float:
    total = sum(counter.values())
    if total == 0:
        return 0.0
    ent = 0.0
    for c in counter.values():
        p = c / total
        ent -= p * math.log2(p)
    return ent


def extract_features(pcap: Path, decode_ports: Optional[List[int]] = None) -> Dict[str, Any]:
    decode_ports = decode_ports or DEFAULT_DECODE_PORTS
    times, func_codes, fc6_addrs, frame_lens, flows = run_tshark(pcap, decode_ports)

    if not times:
        return {"file": pcap.name, "path": str(pcap), "ok": False, "decode_ports": decode_ports}

    total = len(times)
    duration = (max(times) - min(times)) if total > 1 else 0.0
    pkts_per_sec = (total / duration) if duration > 0 else float("inf")

    fc_counter = collections.Counter(func_codes)
    fc3 = fc_counter.get("3", 0)
    fc6 = fc_counter.get("6", 0)

    fc6_addr_counts = collections.Counter(
        addr for fc, addr in zip(func_codes, fc6_addrs) if fc == "6" and addr >= 0
    )
    fc6_entropy = _entropy_from_counts(fc6_addr_counts) if fc6_addr_counts else 0.0

    flow_counts = collections.Counter(flows)

    ports_seen_dst = collections.Counter()
    for f in flows:
        try:
            dport = f.split("->")[1].strip().split(":")[-1]
            ports_seen_dst[dport] += 1
        except Exception:
            pass

    mean_len = sum(frame_lens) / len(frame_lens) if frame_lens else 0.0
    var = (sum((x - mean_len) ** 2 for x in frame_lens) / len(frame_lens)) if frame_lens else 0.0
    std_len = var ** 0.5

    return {
        "file": pcap.name,
        "path": str(pcap),
        "ok": True,
        "decode_ports": decode_ports,
        "total_pkts": total,
        "duration_s": duration,
        "pkts_per_sec": pkts_per_sec,
        "fc3_count": fc3,
        "fc6_count": fc6,
        "fc6_distinct_addrs": len(fc6_addr_counts),
        "fc6_entropy": fc6_entropy,
        "mean_frame_len": mean_len,
        "std_frame_len": std_len,
        "num_flows": len(flow_counts),
        "flow_top3": flow_counts.most_common(3),
        "ports_seen_dst": dict(ports_seen_dst),
    }


def analyze_pcap(pcap: Path) -> None:
    feats = extract_features(pcap)

    print(f"\n=== {pcap.name} ===")
    print(f"Ścieżka: {pcap}")

    if not feats.get("ok", False):
        print("Brak pakietów Modbus lub problem z tshark.")
        print(f"TIP: decode_ports={feats.get('decode_ports')}; oraz upewnij się że dumpcap łapie 1502 (BPF: tcp port 502 or tcp port 1502).")
        return

    print(f"Łącznie pakietów Modbus: {feats['total_pkts']}")
    print(f"Czas trwania śladu: {feats['duration_s']:.3f} s")
    print(f"Średnio pakietów/s: {feats['pkts_per_sec']:.1f}")
    print(f"FC3: {feats['fc3_count']} | FC6: {feats['fc6_count']}")
    print(f"FC6 distinct addrs: {feats['fc6_distinct_addrs']} | FC6 entropy: {feats['fc6_entropy']:.3f} bit")
    print(f"Frame len mean={feats['mean_frame_len']:.1f}B | std={feats['std_frame_len']:.1f}B")
    print(f"Flows: {feats['num_flows']} | top3: {feats['flow_top3']}")
    print(f"Ports seen (dst): {feats['ports_seen_dst']}")


def find_pcap_dir() -> Path:
    this_dir = Path(__file__).resolve().parent
    project_root = this_dir.parent
    return project_root / "capture" / "pcap"


def list_pcaps(pcap_dir: Path) -> List[Path]:
    if not pcap_dir.exists():
        return []
    files = [p for p in pcap_dir.iterdir() if p.is_file() and p.suffix.lower() in PCAP_EXTENSIONS]
    files.sort(key=lambda p: p.stat().st_mtime)
    return files


def choose_files_interactive(files: List[Path]) -> List[Path]:
    if not files:
        print("Brak plików .pcap/.pcapng w katalogu capture/pcap.")
        return []

    print("Dostępne pliki pcap (najnowsze na dole):")
    for idx, p in enumerate(files, start=1):
        size_kb = p.stat().st_size / 1024
        print(f"{idx:2d}) {p.name:50s} ({size_kb:6.1f} KB)")

    raw = input("Wybierz pliki po numerach (np. 1 lub 1,3,5): ").strip()
    if not raw:
        print("Nie wybrano żadnego pliku.")
        return []

    indices: List[int] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            indices.append(int(part))
        except ValueError:
            print(f"Pomijam niepoprawny numer: {part!r}")

    chosen: List[Path] = []
    for n in indices:
        if 1 <= n <= len(files):
            chosen.append(files[n - 1])
        else:
            print(f"Numer poza zakresem: {n}")

    uniq: List[Path] = []
    seen = set()
    for p in chosen:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq


def main(argv: List[str]) -> None:
    if len(argv) > 1:
        for arg in argv[1:]:
            pcap = Path(arg)
            if not pcap.exists():
                print(f"\n=== {pcap} ===")
                print("Plik nie istnieje, pomijam.")
                continue
            analyze_pcap(pcap)
        return

    pcap_dir = find_pcap_dir()
    files = list_pcaps(pcap_dir)
    chosen = choose_files_interactive(files)
    for p in chosen:
        analyze_pcap(p)


if __name__ == "__main__":
    main(sys.argv)

