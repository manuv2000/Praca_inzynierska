from pathlib import Path
from typing import Dict, Any, List
import json

from analysis.quick_modbus_stats import run_tshark_rows, rows_to_packets, window_features

DEFAULT_DECODE_PORTS = [502, 1502]

def load_feature_order(features_json: Path) -> List[str]:
    payload = json.loads(features_json.read_text(encoding="utf-8"))
    # jeżeli masz {"features":[...]}:
    if isinstance(payload, dict) and "features" in payload:
        return payload["features"]
    # albo jeżeli to lista:
    if isinstance(payload, list):
        return payload
    raise ValueError("Nieznany format features.json")

def extract_last_window_features(pcap: Path, window_s: float = 5.0) -> Dict[str, float]:
    rows = run_tshark_rows(pcap, DEFAULT_DECODE_PORTS)
    packets = rows_to_packets(rows)
    wins = window_features(packets, window_s=window_s)
    if not wins:
        return {}
    # bierzemy ostatnie okno
    w = wins[-1]
    # zamiana do floatów (bez metadanych)
    return {k: float(w[k]) for k in w.keys() if k not in ("win_index", "t_start", "t_end")}
