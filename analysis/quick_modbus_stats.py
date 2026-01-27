# analysis/quick_modbus_stats.py

import argparse
import collections
import csv
import json
import math
import shutil
import subprocess
import sys
from dataclasses import dataclass, replace
from pathlib import Path
from typing import List, Tuple, Dict, Any, Optional, Iterable
from statistics import median

PCAP_EXTENSIONS = (".pcap", ".pcapng")
TSHARK_FIXED_PATH = r"C:\Program Files\Wireshark\tshark.exe"

DEFAULT_DECODE_PORTS = [502, 1502]


# -------------------------
# tshark runner (data_extract)
# -------------------------

def _get_tshark_exe() -> str:
    exe = shutil.which("tshark")
    return exe if exe else TSHARK_FIXED_PATH


def _try_tshark(cmd: List[str]) -> Tuple[int, str, str]:
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, err = proc.communicate()
    return proc.returncode, out, err


def _build_tshark_cmd(pcap: Path, decode_ports: List[int], proto: str, fields: List[str]) -> List[str]:
    tshark_exe = _get_tshark_exe()

    cmd = [tshark_exe]
    for p in decode_ports:
        cmd += ["-d", f"tcp.port=={p},{proto}"]

    # ważne: header=n daje stabilne parsowanie
    cmd += [
        "-r", str(pcap),
        "-Y", "modbus",          # po poprawnym decode-as pojawi się warstwa modbus
        "-T", "fields",
        "-E", "separator=\t",
        "-E", "header=n",
        "-E", "occurrence=f",    # first occurrence
    ]

    for f in fields:
        cmd += ["-e", f]

    return cmd

FC16_QTY_FIELDS = [
    "modbus.word_cnt",
    "modbus.quantity",
    "modbus.quantity_of_regs",
    "modbus.regs_cnt",
]

def _probe_qty_field(pcap: Path, decode_ports: List[int], proto: str) -> Optional[str]:
    """
    Sprawdza które pole quantity dla FC16 jest dostępne w lokalnym tshark.
    Zwraca nazwę pola albo None.
    """
    base_fields = [
        "frame.time_epoch",
        "frame.len",
        "ip.src",
        "ip.dst",
        "tcp.srcport",
        "tcp.dstport",
        "tcp.stream",
        "modbus.func_code",
        "modbus.reference_num",
    ]

    for fqty in FC16_QTY_FIELDS:
        fields = base_fields + [fqty]
        cmd = _build_tshark_cmd(pcap, decode_ports, proto, fields)
        _, out, err = _try_tshark(cmd)

        # jeśli tshark krzyczy o niepoprawnych polach – próbujemy następne
        if "Some fields aren't valid" in err:
            continue
        if "isn't valid for layer type" in err or "Valid protocols for layer type" in err:
            continue

        # OK – pole istnieje
        return fqty

    return None
def run_tshark_rows(pcap: Path, decode_ports: List[int]) -> List[Dict[str, str]]:
    """
    Zwraca listę rekordów (dict: field->str) z tshark.
    Dobiera protokół decode-as oraz pole quantity dla FC16 zależnie od wersji tshark.
    """
    proto_candidates = ["mbtcp", "modbus.tcp", "modbus"]

    # pola stałe (zawsze chcemy je mieć)
    base_fields = [
        "frame.time_epoch",
        "frame.len",
        "ip.src",
        "ip.dst",
        "tcp.srcport",
        "tcp.dstport",
        "tcp.stream",
        "modbus.func_code",
        "modbus.reference_num",
    ]

    last_err = ""
    out_text = ""
    used_fields: List[str] = []

    for proto in proto_candidates:
        qty_field = _probe_qty_field(pcap, decode_ports, proto)
        fields = list(base_fields)
        if qty_field:
            fields.append(qty_field)

        cmd = _build_tshark_cmd(pcap, decode_ports, proto, fields)
        code, out, err = _try_tshark(cmd)

        # decode-as nie pasuje -> próbuj kolejny proto
        if "isn't valid for layer type" in err or "Valid protocols for layer type" in err:
            last_err = err.strip()
            continue

        # jeśli mimo probe nadal są invalid fields, spróbuj bez qty_field (żeby nie wywalić całej analizy)
        if "Some fields aren't valid" in err:
            cmd2 = _build_tshark_cmd(pcap, decode_ports, proto, base_fields)
            code2, out2, err2 = _try_tshark(cmd2)
            if "Some fields aren't valid" not in err2 and not (
                "isn't valid for layer type" in err2 or "Valid protocols for layer type" in err2
            ):
                out_text = out2
                used_fields = list(base_fields)
                last_err = err2.strip()
                break

            last_err = err.strip()
            continue

        out_text = out
        used_fields = fields
        last_err = err.strip()
        break

    if not out_text:
        if last_err:
            print("tshark stderr:", last_err)
        return []

    rows: List[Dict[str, str]] = []
    for line in out_text.splitlines():
        line = line.strip()
        if not line:
            continue

        parts = line.split("\t")
        if len(parts) != len(used_fields):
            parts = (parts + [""] * len(used_fields))[:len(used_fields)]

        row = {used_fields[i]: parts[i].strip() for i in range(len(used_fields))}
        rows.append(row)

    return rows

def _as_output_path(base: Path, pcap: Path, suffix: str) -> Path:
    """
    Jeśli user poda katalog (istniejący lub "dir-like") -> dopnij nazwę pliku.
    Jeśli poda plik -> użyj wprost.
    """
    base_str = str(base)
    is_dir_like = base_str.endswith(("/", "\\")) or base.exists() and base.is_dir() or (base.suffix == "")

    if is_dir_like:
        base.mkdir(parents=True, exist_ok=True)
        return base / f"{pcap.stem}{suffix}"
    else:
        base.parent.mkdir(parents=True, exist_ok=True)
        return base


def _first_int(*candidates: str) -> Optional[int]:
    for c in candidates:
        if not c:
            continue
        try:
            return int(float(c))
        except Exception:
            continue
    return None


def _first_float(x: str) -> Optional[float]:
    if not x:
        return None
    try:
        return float(x)
    except Exception:
        return None


@dataclass(frozen=True)
class PacketRecord:
    ts: float
    frame_len: int
    fc: str
    addr: Optional[int]
    count: Optional[int]          # np. FC16 quantity
    ip_src: str
    ip_dst: str
    sport: str
    dport: str
    tcp_stream: str
    direction: str
    delta_t: Optional[float]

    @property
    def flow(self) -> str:
        return f"{self.ip_src}:{self.sport} -> {self.ip_dst}:{self.dport}"

def infer_direction(sport: str, dport: str, server_ports: set[str]) -> str:
    # server_ports to porty "serwera" modbus (502/1502) jako stringi
    if dport in server_ports:
        return "c2s"
    if sport in server_ports:
        return "s2c"
    return "other"


def rows_to_packets(
    rows: List[Dict[str, str]],
    *,
    server_ports: Optional[set[str]] = None
) -> List["PacketRecord"]:

    if server_ports is None:
        server_ports = {str(p) for p in DEFAULT_DECODE_PORTS}  # {"502","1502"}

    packets: List[PacketRecord] = []

    for r in rows:
        ts = _first_float(r.get("frame.time_epoch", ""))
        if ts is None:
            continue

        fc = (r.get("modbus.func_code", "") or "").strip()
        if not fc:
            continue

        frame_len = _first_int(r.get("frame.len", "")) or 0
        addr = _first_int(r.get("modbus.reference_num", ""))

        # FC16 qty: bierz pierwsze dostępne pole (różne wersje tshark)
        count = _first_int(
            r.get("modbus.word_cnt", ""),
            r.get("modbus.quantity", ""),
            r.get("modbus.quantity_of_regs", ""),
            r.get("modbus.regs_cnt", ""),
        )

        ip_src = r.get("ip.src", "") or ""
        ip_dst = r.get("ip.dst", "") or ""
        sport = r.get("tcp.srcport", "") or ""
        dport = r.get("tcp.dstport", "") or ""
        tcp_stream = r.get("tcp.stream", "") or ""

        packets.append(PacketRecord(
            ts=ts,
            frame_len=frame_len,
            fc=fc,
            addr=addr,
            count=count,
            ip_src=ip_src,
            ip_dst=ip_dst,
            sport=sport,
            dport=dport,
            tcp_stream=tcp_stream,
            direction=infer_direction(sport, dport, server_ports),
            delta_t=None,
        ))

    return packets


def add_interarrival(packets: List[PacketRecord]) -> List[PacketRecord]:
    packets = sorted(packets, key=lambda p: p.ts)
    out: List[PacketRecord] = []
    prev_ts: Optional[float] = None
    for p in packets:
        dt = (p.ts - prev_ts) if prev_ts is not None else None
        out.append(replace(p, delta_t=dt))
        prev_ts = p.ts
    return out

# -------------------------
# feature utils (data_process)
# -------------------------

def _entropy_from_counts(counter: collections.Counter) -> float:
    total = sum(counter.values())
    if total == 0:
        return 0.0
    ent = 0.0
    for c in counter.values():
        p = c / total
        ent -= p * math.log2(p)
    return ent


def _mean_std(nums: List[float]) -> Tuple[float, float]:
    if not nums:
        return 0.0, 0.0
    m = sum(nums) / len(nums)
    var = sum((x - m) ** 2 for x in nums) / len(nums)
    return m, var ** 0.5


def extract_summary_features(pcap: Path, packets: List[PacketRecord], decode_ports: List[int]) -> Dict[str, Any]:
    if not packets:
        return {"file": pcap.name, "path": str(pcap), "ok": False, "decode_ports": decode_ports}

    times = [p.ts for p in packets]
    total = len(packets)
    duration = (max(times) - min(times)) if total > 1 else 0.0
    pkts_per_sec = (total / duration) if duration > 0 else float("inf")

    fc_counter = collections.Counter(p.fc for p in packets)
    fc3 = fc_counter.get("3", 0)
    fc6 = fc_counter.get("6", 0)
    fc16 = fc_counter.get("16", 0)

    # addr stats for FC6 and FC16 (osobno)
    fc6_addr_counts = collections.Counter(p.addr for p in packets if p.fc == "6" and p.addr is not None)
    fc16_addr_counts = collections.Counter(p.addr for p in packets if p.fc == "16" and p.addr is not None)

    fc6_entropy = _entropy_from_counts(fc6_addr_counts) if fc6_addr_counts else 0.0
    fc16_entropy = _entropy_from_counts(fc16_addr_counts) if fc16_addr_counts else 0.0

    flows = [p.flow for p in packets]
    flow_counts = collections.Counter(flows)

    ports_seen_dst = collections.Counter(p.dport for p in packets if p.dport)

    frame_lens = [p.frame_len for p in packets if p.frame_len is not None]
    mean_len, std_len = _mean_std([float(x) for x in frame_lens])

    # FC16 count stats (quantity)
    fc16_counts = [float(p.count) for p in packets if p.fc == "16" and p.count is not None]
    fc16_count_mean, fc16_count_std = _mean_std(fc16_counts)
    fc16_count_max = max(fc16_counts) if fc16_counts else 0.0

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
        "fc16_count": fc16,
        "fc6_distinct_addrs": len(fc6_addr_counts),
        "fc6_entropy": fc6_entropy,
        "fc16_distinct_addrs": len(fc16_addr_counts),
        "fc16_entropy": fc16_entropy,
        "fc16_quantity_mean": fc16_count_mean,
        "fc16_quantity_std": fc16_count_std,
        "fc16_quantity_max": fc16_count_max,
        "mean_frame_len": mean_len,
        "std_frame_len": std_len,
        "num_flows": len(flow_counts),
        "flow_top3": flow_counts.most_common(3),
        "ports_seen_dst": dict(ports_seen_dst),
    }

def build_windows_report(
    *,
    pcap: Path,
    windows_csv: Optional[Path],
    windows: List[Dict[str, Any]],
    window_s: float,
    # progi – ustawiamy rozsądne defaulty
    min_rows: int = 2,
    min_total_pkts: int = 50,
    warn_pkts_per_s_low: float = 5.0,
    warn_pkts_per_s_high: float = 200.0,
    warn_top_flow_share: float = 0.9,
) -> Dict[str, Any]:
    errors = []
    warnings = []

    if not windows:
        errors.append("no_windows")
        status = "FAIL"
        return {
            "pcap": str(pcap),
            "windows_csv": str(windows_csv) if windows_csv else None,
            "report": {
                "status": status,
                "errors": errors,
                "warnings": warnings,
                "stats": {},
                "params": {
                    "window_s": window_s,
                    "min_rows": min_rows,
                    "min_total_pkts": min_total_pkts,
                    "warn_pkts_per_s_low": warn_pkts_per_s_low,
                    "warn_pkts_per_s_high": warn_pkts_per_s_high,
                    "warn_top_flow_share": warn_top_flow_share,
                }
            }
        }

    pkts_per_s = [float(w.get("pkts_per_s", 0.0)) for w in windows]
    total_pkts = int(sum(int(w.get("n_pkts", 0)) for w in windows))
    top_flow_share = [float(w.get("top_flow_share", 0.0)) for w in windows]

    # feature-presence
    any_fc16 = any(int(w.get("fc16", 0)) > 0 for w in windows)
    any_zero_flows = any(int(w.get("n_flows", 0)) == 0 for w in windows)

    # stats
    med = statistics.median(pkts_per_s) if pkts_per_s else 0.0
    mn = min(pkts_per_s) if pkts_per_s else 0.0
    mx = max(pkts_per_s) if pkts_per_s else 0.0
    max_tfs = max(top_flow_share) if top_flow_share else 0.0

    # basic validity
    if len(windows) < min_rows:
        errors.append(f"too_few_windows(<{min_rows})")
    if total_pkts < min_total_pkts:
        errors.append(f"too_few_total_pkts(<{min_total_pkts})")

    # warnings
    if med < warn_pkts_per_s_low:
        warnings.append(f"median_pkts_per_s_low(<{warn_pkts_per_s_low})")
    if med > warn_pkts_per_s_high:
        warnings.append(f"median_pkts_per_s_high(>{warn_pkts_per_s_high})")
    if max_tfs > warn_top_flow_share:
        warnings.append(f"top_flow_share_high(>{warn_top_flow_share})")

    status = "OK"
    if errors:
        status = "FAIL"
    elif warnings:
        status = "WARN"

    return {
        "pcap": str(pcap),
        "windows_csv": str(windows_csv) if windows_csv else None,
        "report": {
            "status": status,
            "errors": errors,
            "warnings": warnings,
            "stats": {
                "rows": len(windows),
                "total_pkts": total_pkts,
                "median_pkts_per_s": med,
                "min_pkts_per_s": mn,
                "max_pkts_per_s": mx,
                "max_top_flow_share": max_tfs,
                "any_fc16": bool(any_fc16),
                "any_zero_flows": bool(any_zero_flows),
            },
            "params": {
                "window_s": float(window_s),
                "min_rows": int(min_rows),
                "min_total_pkts": int(min_total_pkts),
                "warn_pkts_per_s_low": float(warn_pkts_per_s_low),
                "warn_pkts_per_s_high": float(warn_pkts_per_s_high),
                "warn_top_flow_share": float(warn_top_flow_share),
            }
        }
    }


def window_features(
    packets: List[PacketRecord],
    window_s: float,
) -> List[Dict[str, Any]]:
    """
    Agregacja featurów w oknach czasowych.
    """
    if not packets:
        return []
    packets = sorted(packets, key=lambda p: p.ts)
    t0 = packets[0].ts
    t_end = packets[-1].ts
    if window_s <= 0:
        raise ValueError("window_s must be > 0")

    out: List[Dict[str, Any]] = []
    i = 0
    n = len(packets)

    w = 0
    t_left = t0
    while t_left <= t_end + 1e-9:
        t_right = t_left + window_s

        bucket: List[PacketRecord] = []
        while i < n and packets[i].ts < t_right:
            bucket.append(packets[i])
            i += 1

        if bucket:
            fc_counter = collections.Counter(p.fc for p in bucket)
            flows = collections.Counter(p.flow for p in bucket)

            fc6_addr_counts = collections.Counter(p.addr for p in bucket if p.fc == "6" and p.addr is not None)
            fc16_addr_counts = collections.Counter(p.addr for p in bucket if p.fc == "16" and p.addr is not None)

            fc16_counts = [float(p.count) for p in bucket if p.fc == "16" and p.count is not None]
            fc16_count_mean, fc16_count_std = _mean_std(fc16_counts)
            fc16_count_max = max(fc16_counts) if fc16_counts else 0.0

            lens = [float(p.frame_len) for p in bucket if p.frame_len is not None]
            mean_len, std_len = _mean_std(lens)

            total = len(bucket)
            # top-flow share: czy jeden flow dominuje
            top_flow_share = (flows.most_common(1)[0][1] / total) if flows and total else 0.0

            out.append({
                "win_index": w,
                "t_start": t_left - t0,
                "t_end": t_right - t0,
                "n_pkts": total,
                "pkts_per_s": total / window_s,
                "fc3": fc_counter.get("3", 0),
                "fc6": fc_counter.get("6", 0),
                "fc16": fc_counter.get("16", 0),
                "n_flows": len(flows),
                "top_flow_share": top_flow_share,
                "fc6_addr_entropy": _entropy_from_counts(fc6_addr_counts) if fc6_addr_counts else 0.0,
                "fc6_addr_distinct": len(fc6_addr_counts),
                "fc16_addr_entropy": _entropy_from_counts(fc16_addr_counts) if fc16_addr_counts else 0.0,
                "fc16_addr_distinct": len(fc16_addr_counts),
                "fc16_qty_mean": fc16_count_mean,
                "fc16_qty_std": fc16_count_std,
                "fc16_qty_max": fc16_count_max,
                "frame_len_mean": mean_len,
                "frame_len_std": std_len,
            })

        w += 1
        t_left = t_right

    return out



def validate_windows(
    wins: List[Dict[str, Any]],
    *,
    window_s: float,
    min_rows: int = 2,
    min_total_pkts: int = 50,
    warn_pkts_per_s_low: float = 5.0,
    warn_pkts_per_s_high: float = 200.0,
    warn_top_flow_share: float = 0.90,
) -> Dict[str, Any]:
    """
    Zwraca raport walidacji dla okien czasowych.
    status: OK / WARN / FAIL
    """
    report = {
        "status": "OK",
        "errors": [],
        "warnings": [],
        "stats": {},
        "params": {
            "window_s": float(window_s),
            "min_rows": int(min_rows),
            "min_total_pkts": int(min_total_pkts),
            "warn_pkts_per_s_low": float(warn_pkts_per_s_low),
            "warn_pkts_per_s_high": float(warn_pkts_per_s_high),
            "warn_top_flow_share": float(warn_top_flow_share),
        }
    }

    if not wins:
        report["status"] = "FAIL"
        report["errors"].append("no_windows_generated")
        return report

    rows = len(wins)
    total_pkts = sum(int(w.get("n_pkts", 0) or 0) for w in wins)
    pkps = [float(w.get("pkts_per_s", 0.0) or 0.0) for w in wins]
    top_share = [float(w.get("top_flow_share", 0.0) or 0.0) for w in wins]

    any_fc16 = any(int(w.get("fc16", 0) or 0) > 0 for w in wins)
    any_zero_flows = any(int(w.get("n_flows", 0) or 0) == 0 for w in wins)

    report["stats"] = {
        "rows": rows,
        "total_pkts": total_pkts,
        "median_pkts_per_s": float(median(pkps)) if pkps else 0.0,
        "min_pkts_per_s": float(min(pkps)) if pkps else 0.0,
        "max_pkts_per_s": float(max(pkps)) if pkps else 0.0,
        "max_top_flow_share": float(max(top_share)) if top_share else 0.0,
        "any_fc16": bool(any_fc16),
        "any_zero_flows": bool(any_zero_flows),
    }

    # FAIL conditions
    if rows < min_rows:
        report["status"] = "FAIL"
        report["errors"].append(f"too_few_rows(<{min_rows})")

    if total_pkts < min_total_pkts:
        report["status"] = "FAIL"
        report["errors"].append(f"too_few_packets(<{min_total_pkts})")

    # WARN conditions
    if pkps and (report["stats"]["median_pkts_per_s"] < warn_pkts_per_s_low):
        report["warnings"].append(f"low_median_pkts_per_s(<{warn_pkts_per_s_low})")

    if pkps and (report["stats"]["median_pkts_per_s"] > warn_pkts_per_s_high):
        report["warnings"].append(f"high_median_pkts_per_s(>{warn_pkts_per_s_high})")

    if top_share and report["stats"]["max_top_flow_share"] > warn_top_flow_share:
        report["warnings"].append(f"top_flow_share_high(>{warn_top_flow_share})")

    if any_zero_flows:
        report["warnings"].append("some_windows_have_zero_flows")

    # Jeśli są warnings a nie ma FAIL -> WARN
    if report["status"] != "FAIL" and report["warnings"]:
        report["status"] = "WARN"

    return report


# -------------------------
# exports (data_extract/data_process outputs)
# -------------------------

def export_packets_jsonl(packets: List[PacketRecord], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for p in packets:
            f.write(json.dumps({
                "ts": p.ts,
                "frame_len": p.frame_len,
                "fc": p.fc,
                "addr": p.addr,
                "count": p.count,
                "ip_src": p.ip_src,
                "ip_dst": p.ip_dst,
                "sport": p.sport,
                "dport": p.dport,
                "tcp_stream": p.tcp_stream,
                "flow": p.flow,
            }, ensure_ascii=False) + "\n")


def export_windows_csv(rows: List[Dict[str, Any]], out_path: Path) -> None:
    if not rows:
        return
    out_path.parent.mkdir(parents=True, exist_ok=True)
    keys = list(rows[0].keys())
    with out_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        w.writerows(rows)


# -------------------------
# CLI / 기존 behavior
# -------------------------

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
        print(f"{idx:2d}) {p.name:60s} ({size_kb:7.1f} KB)")

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


def print_summary(pcap: Path, feats: Dict[str, Any]) -> None:
    print(f"\n=== {pcap.name} ===")
    print(f"Ścieżka: {pcap}")

    if not feats.get("ok", False):
        print("Brak pakietów Modbus lub problem z tshark.")
        print(f"TIP: decode_ports={feats.get('decode_ports')}; upewnij się że BPF obejmuje 502/1502.")
        return

    print(f"Łącznie pakietów Modbus: {feats['total_pkts']}")
    print(f"Czas trwania śladu: {feats['duration_s']:.3f} s")
    print(f"Średnio pakietów/s: {feats['pkts_per_sec']:.1f}")
    print(f"FC3: {feats['fc3_count']} | FC6: {feats['fc6_count']} | FC16: {feats['fc16_count']}")
    print(f"FC6 distinct addrs: {feats['fc6_distinct_addrs']} | FC6 entropy: {feats['fc6_entropy']:.3f} bit")
    print(f"FC16 distinct addrs: {feats['fc16_distinct_addrs']} | FC16 entropy: {feats['fc16_entropy']:.3f} bit")
    print(f"FC16 qty mean={feats['fc16_quantity_mean']:.2f} std={feats['fc16_quantity_std']:.2f} max={feats['fc16_quantity_max']:.0f}")
    print(f"Frame len mean={feats['mean_frame_len']:.1f}B | std={feats['std_frame_len']:.1f}B")
    print(f"Flows: {feats['num_flows']} | top3: {feats['flow_top3']}")
    print(f"Ports seen (dst): {feats['ports_seen_dst']}")


def main(argv: List[str]) -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("pcaps", nargs="*", help="Ścieżki do pcapów. Jeśli puste -> wybór interaktywny z capture/pcap.")
    ap.add_argument("--decode-port", action="append", type=int, default=None, help="Port do decode-as (można powtórzyć).")
    ap.add_argument("--export-packets", default=None, help="Zapisz rekordy pakietów do JSONL (data_extract).")
    ap.add_argument("--export-windows", default=None, help="Zapisz cechy okien do CSV (data_process).")
    ap.add_argument("--window-s", type=float, default=5.0, help="Szerokość okna dla cech (sekundy).")
    ap.add_argument("--export-report", default=None, help="Zapisz report JSON dla windows CSV (obok pliku CSV).")

    args = ap.parse_args(argv[1:])

    decode_ports = args.decode_port if args.decode_port else DEFAULT_DECODE_PORTS

    if args.pcaps:
        pcaps = [Path(p) for p in args.pcaps]
    else:
        pcap_dir = find_pcap_dir()
        files = list_pcaps(pcap_dir)
        pcaps = choose_files_interactive(files)

    for pcap in pcaps:
        if not pcap.exists():
            print(f"\n=== {pcap} ===")
            print("Plik nie istnieje, pomijam.")
            continue

        rows = run_tshark_rows(pcap, decode_ports)
        packets = rows_to_packets(rows)
        feats = extract_summary_features(pcap, packets, decode_ports)
        print_summary(pcap, feats)

        if args.export_packets:
            out_base = Path(args.export_packets)
            out = _as_output_path(out_base, pcap, ".jsonl")
            export_packets_jsonl(packets, out)

        if args.export_windows:
            out_base = Path(args.export_windows)
            out = _as_output_path(out_base, pcap, f".win{args.window_s:g}s.csv")
            wins = window_features(packets, window_s=args.window_s)
            export_windows_csv(wins, out)

            if args.export_report:
                rep_dir = Path(args.export_report)
                rep_dir.mkdir(parents=True, exist_ok=True)
                rep_path = Path(str(out) + ".report.json")
                report = build_report(pcap, feats, wins)
                rep_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
                print(f"[OK] report saved: {rep_path}")


            # --- validation report next to CSV ---
            rep = validate_windows(wins, window_s=args.window_s)
            rep_path = out.with_suffix(out.suffix + ".report.json")
            rep_payload = {
                "pcap": str(pcap),
                "windows_csv": str(out),
                "report": rep,
            }
            rep_path.write_text(json.dumps(rep_payload, indent=2, ensure_ascii=False), encoding="utf-8")

            print(f"[{rep['status']}] windows report: {rep_path}")
            if rep["status"] == "FAIL":
                print("  errors:", rep["errors"])
            elif rep["status"] == "WARN":
                print("  warnings:", rep["warnings"])

            print(f"[OK] windows saved: {out} (rows={len(wins)})")


if __name__ == "__main__":
    main(sys.argv)