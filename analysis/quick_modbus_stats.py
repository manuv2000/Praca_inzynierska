# analysis/quick_modbus_stats.py

import collections
import math
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Tuple, Dict, Any

PCAP_EXTENSIONS = (".pcap", ".pcapng")
TSHARK_FIXED_PATH = r"C:\Program Files\Wireshark\tshark.exe"


def _get_tshark_exe() -> str:
    exe = shutil.which("tshark")
    if exe:
        return exe
    return TSHARK_FIXED_PATH


def run_tshark(pcap: Path) -> Tuple[List[float], List[str], List[int], List[int]]:
    """
    Zwraca:
      - lista czasów (epoch),
      - lista kodów funkcji Modbus (string),
      - lista adresów (dla FC6; dla innych -1),
      - lista długości ramek (frame.len)
    """
    tshark_exe = _get_tshark_exe()

    cmd = [
        tshark_exe,
        "-r", str(pcap),
        "-Y", "modbus",
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "modbus.func_code",
        "-e", "modbus.reference_num",  # adres rejestru
        "-e", "frame.len",
    ]

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
    except FileNotFoundError:
        print("ERROR: nie znaleziono programu `tshark`.")
        print("Zainstaluj Wireshark / tshark i popraw TSHARK_FIXED_PATH.")
        return [], [], [], []

    times: List[float] = []
    func_codes: List[str] = []
    fc6_addrs: List[int] = []     # -1 gdy nie FC6
    frame_lens: List[int] = []

    assert proc.stdout is not None
    for line in proc.stdout:
        line = line.strip()
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) < 4:
            continue

        # czas
        try:
            t = float(parts[0])
        except ValueError:
            continue

        fc = parts[1].strip()
        addr_raw = parts[2].strip()
        len_raw = parts[3].strip()

        # adres rejestru tylko dla FC6
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

        times.append(t)
        func_codes.append(fc)
        fc6_addrs.append(addr)
        frame_lens.append(flen)

    proc.wait()
    return times, func_codes, fc6_addrs, frame_lens


def _entropy_from_counts(counter: collections.Counter) -> float:
    total = sum(counter.values())
    if total == 0:
        return 0.0
    ent = 0.0
    for c in counter.values():
        p = c / total
        ent -= p * math.log2(p)
    return ent


def extract_features(pcap: Path) -> Dict[str, Any]:
    times, func_codes, fc6_addrs, frame_lens = run_tshark(pcap)

    if not times:
        return {
            "file": pcap.name,
            "path": str(pcap),
            "ok": False,
        }

    total = len(times)
    duration = max(times) - min(times) if len(times) > 1 else 0.0
    pkts_per_sec = total / duration if duration > 0 else float("inf")

    fc_counter = collections.Counter(func_codes)
    fc3 = fc_counter.get("3", 0)
    fc6 = fc_counter.get("6", 0)
    fc3_ratio = fc3 / total if total else 0.0
    fc6_ratio = fc6 / total if total else 0.0

    # statystyki FC6 po adresach
    fc6_addr_counts = collections.Counter(
        addr for fc, addr in zip(func_codes, fc6_addrs) if fc == "6" and addr >= 0
    )
    distinct_fc6_addrs = len(fc6_addr_counts)
    fc6_entropy = _entropy_from_counts(fc6_addr_counts) if fc6_addr_counts else 0.0

    if fc6_addr_counts:
        top_addr, top_cnt = fc6_addr_counts.most_common(1)[0]
        top_share = top_cnt / fc6 if fc6 else 0.0
    else:
        top_addr, top_cnt, top_share = None, 0, 0.0

    if frame_lens:
        n = len(frame_lens)
        mean_len = sum(frame_lens) / n
        var = sum((x - mean_len) ** 2 for x in frame_lens) / n
        std_len = var ** 0.5
    else:
        mean_len = std_len = 0.0

    return {
        "file": pcap.name,
        "path": str(pcap),
        "ok": True,
        "total_pkts": total,
        "duration_s": duration,
        "pkts_per_sec": pkts_per_sec,
        "fc3_count": fc3,
        "fc6_count": fc6,
        "fc3_ratio": fc3_ratio,
        "fc6_ratio": fc6_ratio,
        "fc6_total_writes": fc6,  # alias
        "fc6_distinct_addrs": distinct_fc6_addrs,
        "fc6_entropy": fc6_entropy,
        "fc6_top_addr": top_addr,
        "fc6_top_addr_share": top_share,
        "mean_frame_len": mean_len,
        "std_frame_len": std_len,
    }

def analyze_pcap(pcap: Path) -> None:
    feats = extract_features(pcap)

    print(f"\n=== {pcap.name} ===")
    print(f"Ścieżka: {pcap}")

    if not feats.get("ok", False):
        print("Brak pakietów Modbus lub problem z tshark.")
        return

    total = feats["total_pkts"]
    duration = feats["duration_s"]
    pkts_per_sec = feats["pkts_per_sec"]
    fc3 = feats["fc3_count"]
    fc6 = feats["fc6_count"]
    fc3_ratio = feats["fc3_ratio"]
    fc6_ratio = feats["fc6_ratio"]

    print(f"Łącznie pakietów Modbus: {total}")
    print(f"Czas trwania śladu: {duration:.3f} s")
    print(f"Średnio pakietów/s: {pkts_per_sec:.1f}")
    print("Rozkład kodów funkcji (func_code):")
    if fc3:
        print(f"  FC  3 (Read Holding Registers  ): {fc3} pakietów ({fc3_ratio*100:.1f}%)")
    if fc6:
        print(f"  FC  6 (Write Single Register   ): {fc6} pakietów ({fc6_ratio*100:.1f}%)")
    for fc, cnt in sorted(
        ((k, v) for k, v in collections.Counter(["3" if c == "3" else "OTHER"
                                                 for c in []]).items()),
        key=lambda x: x[0],
    ):
        pass

    # FC6 – analiza adresów
    if fc6:
        print("\n[FC6 – Write Single Register]")
        print(f"  Łącznie zapisów: {fc6}")
        print(f"  Liczba różnych rejestrów: {feats['fc6_distinct_addrs']}")

        times, func_codes, fc6_addrs, _ = run_tshark(pcap)
        addr_counts = collections.Counter(
            addr for fc, addr in zip(func_codes, fc6_addrs) if fc == "6" and addr >= 0
        )
        top5 = addr_counts.most_common(5)
        print("  Top 5 rejestrów (adres -> liczba zapisów, udział):")
        for addr, cnt in top5:
            share = cnt / fc6 * 100 if fc6 else 0.0
            print(f"    HR[{addr}]: {cnt} zapisów ({share:.1f}%)")

        top_addr = feats["fc6_top_addr"]
        top_share = feats["fc6_top_addr_share"] * 100
        ent = feats["fc6_entropy"]
        if top_addr is not None:
            print(f"  Udział najczęściej zapisywanego rejestru HR[{top_addr}]: {top_share:.1f}%")
        print(f"  Entropia rozkładu zapisów FC6: {ent:.3f} bitów")
    else:
        print("\n[FC6 – Write Single Register]")
        print("  Brak zapisów FC6 w tym śladzie.")

    print("\n[Długość ramek]")
    print(f"  Średnia długość ramki: {feats['mean_frame_len']:.1f} bajtów")
    print(f"  Odchylenie std długości: {feats['std_frame_len']:.1f} bajtów")


def find_pcap_dir() -> Path:
    this_dir = Path(__file__).resolve().parent
    project_root = this_dir.parent
    return project_root / "capture" / "pcap"


def list_pcaps(pcap_dir: Path) -> List[Path]:
    if not pcap_dir.exists():
        return []
    files = [
        p for p in pcap_dir.iterdir()
        if p.is_file() and p.suffix.lower() in PCAP_EXTENSIONS
    ]
    files.sort(key=lambda p: p.stat().st_mtime)
    return files


def choose_files_interactive(files: List[Path]) -> List[Path]:
    if not files:
        print("Brak plików .pcap/.pcapng w katalogu capture/pcap.")
        return []

    print("Dostępne pliki pcap (najnowsze na dole):")
    for idx, p in enumerate(files, start=1):
        size_kb = p.stat().st_size / 1024
        print(f"{idx:2d}) {p.name:40s} ({size_kb:6.1f} KB)")

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
    if not uniq:
        print("Po przefiltrowaniu brak poprawnych wyborów.")
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
