import time
from pathlib import Path
from typing import Optional, Tuple, Dict, Any
import csv

from detector.runtime.model_pipeline import Detector  # ten co już masz (IF+AE)

def pick_latest_csv(features_dir: Path) -> Optional[Path]:
    files = sorted(features_dir.glob("*.win5s.csv"), key=lambda p: p.stat().st_mtime)
    return files[-1] if files else None

def file_signature(p: Path) -> Tuple[str, int, int]:
    st = p.stat()
    return (str(p), int(st.st_size), int(st.st_mtime))

def read_last_row(csv_path: Path) -> Optional[Dict[str, str]]:
    # czytamy “ostatni wiersz” bez pandas
    # (dla małych plików OK; u Ciebie to zwykle kilkanaście/kilkadziesiąt wierszy)
    with csv_path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        last = None
        for row in reader:
            last = row
    return last

def parse_features(row: Dict[str, str]) -> Dict[str, float]:
    # bierzemy tylko te kolumny, które są cechami
    drop = {"win_index", "t_start", "t_end"}
    out = {}
    for k, v in row.items():
        if k in drop:
            continue
        try:
            out[k] = float(v)
        except Exception:
            out[k] = 0.0
    return out

def main():
    base = Path(__file__).resolve().parents[2]
    features_dir = base / "capture" / "pcap" / "features"
    artifacts_dir = base / "detector" / "artifacts"

    det = Detector(artifacts_dir)

    last_sig = None
    last_csv = None

    print("[live] watching:", features_dir)

    while True:
        p = pick_latest_csv(features_dir)
        if p is None:
            time.sleep(0.5)
            continue

        sig = file_signature(p)
        if sig == last_sig:
            time.sleep(0.5)
            continue

        row = read_last_row(p)
        if not row:
            last_sig = sig
            time.sleep(0.5)
            continue

        feats = parse_features(row)
        result = det.score(feats)

        # log “czytelny”
        dec = result["decision"]
        if_score = result.get("iforest", {}).get("score", None)
        ae_score = result.get("autoencoder", {}).get("score", None)

        print(
            f"[live] src={p.name}  "
            f"critical={dec.get('critical')} warning={dec.get('warning')} "
            f"IF={if_score:.4f} AE={ae_score:.4f}"
        )

        last_sig = sig
        time.sleep(0.2)

if __name__ == "__main__":
    main()
