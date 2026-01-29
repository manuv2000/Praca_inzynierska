# detector/runtime/ids_live.py
import argparse
import collections
import json
import math
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib  # scikit-learn/joblib
import torch
import torch.nn as nn
import json
from pathlib import Path



DEFAULT_INTERFACE = "Adapter for loopback traffic capture"
BPF_FILTER = "tcp port 502 or tcp port 1502"
DECODE_PORTS = [502, 1502]

FC16_QTY_FIELDS = [
    "modbus.word_cnt",
    "modbus.quantity",
    "modbus.quantity_of_regs",
    "modbus.regs_cnt",
]


# ----------------------------
# Utils: entropy + stats
# ----------------------------
def _entropy_from_counts(counter: collections.Counter) -> float:
    total = sum(counter.values())
    if total == 0:
        return 0.0
    ent = 0.0
    for c in counter.values():
        p = c / total
        ent -= p * math.log2(p)
    return ent

def _load_threshold_value(p: Path) -> float:
    obj = json.loads(p.read_text(encoding="utf-8"))
    # Twoj format: {"quantile":..., "value":...}
    if isinstance(obj, dict) and "value" in obj:
        return float(obj["value"])
    raise KeyError(f"threshold file {p} has no 'value' key: keys={list(obj.keys()) if isinstance(obj, dict) else type(obj)}")

def _mean_std(nums: List[float]) -> Tuple[float, float]:
    if not nums:
        return 0.0, 0.0
    m = sum(nums) / len(nums)
    var = sum((x - m) ** 2 for x in nums) / len(nums)
    return m, var ** 0.5


def _safe_float(x: str) -> Optional[float]:
    try:
        return float(x)
    except Exception:
        return None


def _safe_int(x: str) -> Optional[int]:
    try:
        return int(float(x))
    except Exception:
        return None


# ----------------------------
# Live tshark field probing
# ----------------------------
def _pick_qty_field(tshark_exe: str) -> Optional[str]:
    """
    Żeby uniknąć błędu 'Some fields aren't valid', sprawdzamy dostępność pól przez -G fields.
    """
    try:
        proc = subprocess.run(
            [tshark_exe, "-G", "fields"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
        )
        txt = (proc.stdout or "") + "\n" + (proc.stderr or "")
        for f in FC16_QTY_FIELDS:
            if f in txt:
                return f
        return None
    except Exception:
        return None


def _build_live_tshark_cmd(
    tshark_exe: str,
    interface: str,
    bpf: str,
    decode_ports: List[int],
    qty_field: Optional[str],
) -> Tuple[List[str], List[str]]:
    """
    Zwraca (cmd, fields).
    """
    proto_candidates = ["mbtcp", "modbus.tcp", "modbus"]

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

    fields = list(base_fields)
    if qty_field:
        fields.append(qty_field)

    # Wybieramy pierwszy proto; jeśli tshark na starcie się wysypie, user zmieni w args.
    proto = proto_candidates[0]

    cmd = [tshark_exe, "-l", "-n"]  # line-buffered, no name resolution
    cmd += ["-i", interface]
    cmd += ["-f", bpf]

    for p in decode_ports:
        cmd += ["-d", f"tcp.port=={p},{proto}"]

    cmd += [
        "-Y", "modbus",
        "-T", "fields",
        "-E", "separator=\t",
        "-E", "header=n",
        "-E", "occurrence=f",
    ]

    for f in fields:
        cmd += ["-e", f]

    return cmd, fields

class MLPAutoencoder(torch.nn.Module):
    def __init__(self, n_features: int):
        super().__init__()
        self.net = torch.nn.Sequential(
            torch.nn.Linear(n_features, 16),
            torch.nn.ReLU(),
            torch.nn.Linear(16, 5),
            torch.nn.ReLU(),
            torch.nn.Linear(5, n_features),
        )

    def forward(self, x):
        return self.net(x)
# ----------------------------
# Packet + window aggregation
# ----------------------------
@dataclass
class PacketRecord:
    ts: float
    frame_len: int
    fc: str
    addr: Optional[int]
    count: Optional[int]
    ip_src: str
    ip_dst: str
    sport: str
    dport: str
    tcp_stream: str

    @property
    def flow(self) -> str:
        return f"{self.ip_src}:{self.sport} -> {self.ip_dst}:{self.dport}"


def compute_window_features(bucket: List[PacketRecord]) -> Dict[str, float]:
    fc_counter = collections.Counter(p.fc for p in bucket)
    flows = collections.Counter(p.flow for p in bucket)

    fc6_addr_counts = collections.Counter(p.addr for p in bucket if p.fc == "6" and p.addr is not None)
    fc16_addr_counts = collections.Counter(p.addr for p in bucket if p.fc == "16" and p.addr is not None)

    fc16_counts = [float(p.count) for p in bucket if p.fc == "16" and p.count is not None]
    fc16_mean, fc16_std = _mean_std(fc16_counts)
    fc16_max = max(fc16_counts) if fc16_counts else 0.0

    lens = [float(p.frame_len) for p in bucket if p.frame_len is not None]
    mean_len, std_len = _mean_std(lens)

    total = len(bucket)
    top_flow_share = (flows.most_common(1)[0][1] / total) if flows and total else 0.0

    return {
        "n_pkts": float(total),
        "pkts_per_s": 0.0,  # uzupełni pętla (bo zna window_s)
        "fc3": float(fc_counter.get("3", 0)),
        "fc6": float(fc_counter.get("6", 0)),
        "fc16": float(fc_counter.get("16", 0)),
        "n_flows": float(len(flows)),
        "top_flow_share": float(top_flow_share),
        "fc6_addr_entropy": float(_entropy_from_counts(fc6_addr_counts) if fc6_addr_counts else 0.0),
        "fc6_addr_distinct": float(len(fc6_addr_counts)),
        "fc16_addr_entropy": float(_entropy_from_counts(fc16_addr_counts) if fc16_addr_counts else 0.0),
        "fc16_addr_distinct": float(len(fc16_addr_counts)),
        "fc16_qty_mean": float(fc16_mean),
        "fc16_qty_std": float(fc16_std),
        "fc16_qty_max": float(fc16_max),
        "frame_len_mean": float(mean_len),
        "frame_len_std": float(std_len),
    }


# ----------------------------
# Model loader + scorer (IF + AE)
# ----------------------------
class RuntimeDetector:
    def __init__(self, artifacts_dir: Path):
        self.artifacts_dir = Path(artifacts_dir)

        # features + scaler + IF
        self.features = json.loads(
            (self.artifacts_dir / "features.json").read_text(encoding="utf-8")
        )["features"]
        self.n_features = len(self.features)

        self.scaler = joblib.load(self.artifacts_dir / "scaler.pkl")

        self.iforest = joblib.load(self.artifacts_dir / "iforest.pkl")
        self.if_threshold = _load_threshold_value(self.artifacts_dir / "iforest_threshold.json")

        # AE threshold
        self.ae_threshold = _load_threshold_value(self.artifacts_dir / "ae_threshold.json")

        # AE weights
        ae_path = self.artifacts_dir / "ae_model.pt"
        if not ae_path.exists():
            raise FileNotFoundError(f"Brak pliku: {ae_path}")

        # Zainicjalizuj AE z architekturą zgodną z treningiem (16->16->5->16)
        self.ae_model = MLPAutoencoder(n_features=self.n_features)

        state = torch.load(ae_path, map_location="cpu")

        # jeśli zapis opakowany
        if isinstance(state, dict) and "state_dict" in state:
            state = state["state_dict"]

        if not isinstance(state, dict):
            raise RuntimeError(
                f"Nieoczekiwany format ae_model.pt: {type(state)} "
                f"(spodziewany dict z wagami / state_dict)."
            )

        # zdejmij ewentualny prefix "module."
        if any(k.startswith("module.") for k in state.keys()):
            state = {k.replace("module.", "", 1): v for k, v in state.items()}

        # DEBUG: kluczowe info = shapes
        weight_shapes = [(k, tuple(v.shape)) for k, v in state.items() if k.endswith("weight")]
        print(f"[ids][ae][debug] weights ({len(weight_shapes)}): {weight_shapes}")

        # Weryfikacja, że model_key set pasuje (szybka diagnoza jeśli coś nie gra)
        model_keys = set(self.ae_model.state_dict().keys())
        state_keys = set(state.keys())
        missing = sorted(list(model_keys - state_keys))
        unexpected = sorted(list(state_keys - model_keys))
        if missing or unexpected:
            # tutaj wolę od razu przerwać, bo to znaczy, że architektura się nie zgadza
            raise RuntimeError(
                "[ids][ae] state_dict keys mismatch.\n"
                f"missing (first 20): {missing[:20]}\n"
                f"unexpected (first 20): {unexpected[:20]}"
            )

        # Ładuj NA OSTRO (strict=True). Jak nie pasuje shape -> ma wywalić błąd.
        self.ae_model.load_state_dict(state, strict=True)
        self.ae_model.eval()
        print("[ids][ae] load_state_dict strict=True OK")

    def vectorize(self, feats: Dict[str, float]) -> List[float]:
        return [float(feats.get(k, 0.0)) for k in self.features]

    def score(self, feats: Dict[str, float]) -> Dict[str, Any]:
        x = self.vectorize(feats)
        Xs = self.scaler.transform([x])

        # IsolationForest: score_samples (u Ciebie: większy => bardziej anomalia)
        if_score = float(self.iforest.score_samples(Xs)[0])

        # Autoencoder: MSE rekonstrukcji
        xt = torch.tensor(Xs, dtype=torch.float32)
        with torch.no_grad():
            recon = self.ae_model(xt)
        ae_mse = torch.mean((recon - xt) ** 2, dim=1).cpu().numpy()[0].item()
        ae_score = float(ae_mse)

        if_anom = if_score >= float(self.if_threshold)
        ae_anom = ae_score >= float(self.ae_threshold)

        return {
            "iforest": {"score": if_score, "threshold": float(self.if_threshold), "is_anom": bool(if_anom)},
            "autoencoder": {"score": ae_score, "threshold": float(self.ae_threshold), "is_anom": bool(ae_anom)},
            "raw": {"features": feats},
        }


def _load_threshold_value(p: Path) -> float:
    obj = json.loads(p.read_text(encoding="utf-8"))

    # wariant A: {"threshold": {"value": ...}}
    if isinstance(obj, dict) and "threshold" in obj and isinstance(obj["threshold"], dict) and "value" in obj["threshold"]:
        return float(obj["threshold"]["value"])

    # wariant B: {"threshold_value": ...}
    if isinstance(obj, dict) and "threshold_value" in obj:
        return float(obj["threshold_value"])

    # wariant C: {"value": ...}
    if isinstance(obj, dict) and "value" in obj:
        return float(obj["value"])

    # wariant D: {"model":..., "threshold": {"quantile":..., "value":...}} albo report.json
    # (czasem zapisujesz metryki w reportach)
    if isinstance(obj, dict):
        # spróbuj znaleźć pierwsze wystąpienie klucza "value"
        def _dfs(d):
            if isinstance(d, dict):
                if "value" in d:
                    return d["value"]
                for v in d.values():
                    r = _dfs(v)
                    if r is not None:
                        return r
            return None

        v = _dfs(obj)
        if v is not None:
            return float(v)

    raise KeyError(f"Nie rozpoznano formatu progu w {p}. Klucze top-level: {list(obj.keys()) if isinstance(obj, dict) else type(obj)}")


# ----------------------------
# Live loop (5s windows) + anti-jitter + hysteresis
# ----------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--interface", default=DEFAULT_INTERFACE)
    ap.add_argument("--bpf", default=BPF_FILTER)
    ap.add_argument("--window-s", type=float, default=5.0)
    ap.add_argument("--artifacts", default=str(Path(__file__).resolve().parents[1] / "artifacts"))
    ap.add_argument("--tshark", default="tshark")
    ap.add_argument("--hysteresis", type=int, default=3, help="Ile ostatnich okien trzymać (np. 3).")
    ap.add_argument("--hysteresis-min", type=int, default=2, help="Ile z N musi być anomalią, by podnieść alarm (np. 2 z 3).")
    ap.add_argument("--skip-jitter", action="store_true", help="Pomijaj 1 okno po dużym skoku pkts_per_s.")
    ap.add_argument("--jitter-factor", type=float, default=2.5, help="Skok pkts_per_s > factor*median -> uznaj za przełączenie.")
    args = ap.parse_args()

    artifacts_dir = Path(args.artifacts)
    det = RuntimeDetector(artifacts_dir)

    tshark_exe = args.tshark
    qty_field = _pick_qty_field(tshark_exe)

    cmd, fields = _build_live_tshark_cmd(
        tshark_exe=tshark_exe,
        interface=args.interface,
        bpf=args.bpf,
        decode_ports=DECODE_PORTS,
        qty_field=qty_field,
    )

    print("[ids] interface:", args.interface)
    print("[ids] bpf:", args.bpf)
    print("[ids] window_s:", args.window_s)
    print("[ids] qty_field:", qty_field)
    print("[ids] artifacts:", artifacts_dir)
    print("[ids] starting tshark:", " ".join(cmd))

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
    )

    window_s = float(args.window_s)
    win_start: Optional[float] = None
    bucket: List[PacketRecord] = []

    # hysteresis buffer (True/False)
    hist: List[bool] = []
    pkps_hist: List[float] = []
    skip_next = 0

    def median(xs: List[float]) -> float:
        if not xs:
            return 0.0
        ys = sorted(xs)
        m = len(ys) // 2
        return float(ys[m]) if len(ys) % 2 == 1 else float((ys[m - 1] + ys[m]) / 2)

    try:
        assert proc.stdout is not None

        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue

            parts = line.split("\t")
            if len(parts) != len(fields):
                # niepełna linia -> pomiń
                continue

            row = {fields[i]: parts[i] for i in range(len(fields))}

            ts = _safe_float(row.get("frame.time_epoch", ""))
            if ts is None:
                continue

            fc = (row.get("modbus.func_code", "") or "").strip()
            if not fc:
                continue

            frame_len = _safe_int(row.get("frame.len", "")) or 0
            addr = _safe_int(row.get("modbus.reference_num", ""))

            count = None
            if qty_field:
                count = _safe_int(row.get(qty_field, ""))

            p = PacketRecord(
                ts=ts,
                frame_len=frame_len,
                fc=fc,
                addr=addr,
                count=count,
                ip_src=row.get("ip.src", "") or "",
                ip_dst=row.get("ip.dst", "") or "",
                sport=row.get("tcp.srcport", "") or "",
                dport=row.get("tcp.dstport", "") or "",
                tcp_stream=row.get("tcp.stream", "") or "",
            )

            if win_start is None:
                win_start = ts

            # jeśli pakiet wciąż mieści się w oknie
            if ts < win_start + window_s:
                bucket.append(p)
                continue

            # okno domknięte -> licz cechy i score
            if bucket:
                feats = compute_window_features(bucket)
                feats["pkts_per_s"] = float(len(bucket)) / window_s

                # anti-jitter: gdy pkts_per_s skoczy mocno -> pomiń 1 okno
                pkps = feats["pkts_per_s"]
                pkps_hist.append(pkps)
                med = median(pkps_hist[-5:])

                if args.skip_jitter and med > 0 and pkps > args.jitter_factor * med:
                    skip_next = 1

                result = det.score(feats)
                is_anom_now = bool(result["iforest"]["is_anom"] or result["autoencoder"]["is_anom"])

                # histereza 2/3
                if skip_next > 0:
                    is_anom_now = False
                    skip_next -= 1

                hist.append(is_anom_now)
                hist = hist[-int(args.hysteresis):]

                votes = sum(1 for x in hist if x)
                alarm = votes >= int(args.hysteresis_min)

                print(
                    f"[ids] t={time.strftime('%H:%M:%S')} "
                    f"pkts={int(feats['n_pkts'])} pkps={feats['pkts_per_s']:.1f} "
                    f"IF={result['iforest']['score']:.4f}/{result['iforest']['threshold']:.4f} "
                    f"AE={result['autoencoder']['score']:.4f}/{result['autoencoder']['threshold']:.4f} "
                    f"anom={is_anom_now} alarm={alarm} hist={hist}"
                )

            # przesuń okno do przodu
            # Jeśli jest duża przerwa, przeskocz do "ostatniego" okna
            win_start = ts
            bucket = [p]

    except KeyboardInterrupt:
        print("\n[ids] Ctrl+C -> stop")
    finally:
        try:
            proc.terminate()
        except Exception:
            pass


if __name__ == "__main__":
    main()
