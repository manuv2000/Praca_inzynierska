# analysis/train_lof_unsup.py
from __future__ import annotations

import argparse
import json
import pickle
from pathlib import Path
from typing import Dict, Any

import numpy as np
import pandas as pd
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import RobustScaler


DEFAULT_BASE = Path("data_prepared/unsupervised")
DEFAULT_IN_DIR = DEFAULT_BASE / "step2_features"
DEFAULT_IF_DIR = DEFAULT_BASE / "step3_iforest"
DEFAULT_OUT_DIR = DEFAULT_BASE / "step4_lof"


def _load_csv(path: Path) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(f"Brak pliku: {path}")
    return pd.read_csv(path)


def _load_pickle(path: Path):
    with open(path, "rb") as f:
        return pickle.load(f)


def _save_pickle(obj: object, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        pickle.dump(obj, f)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in_dir", default=str(DEFAULT_IN_DIR))
    ap.add_argument("--if_dir", default=str(DEFAULT_IF_DIR), help="żeby użyć tego samego scaler'a")
    ap.add_argument("--out_dir", default=str(DEFAULT_OUT_DIR))
    ap.add_argument("--quantile", type=float, default=0.99)
    ap.add_argument("--n_neighbors", type=int, default=8)
    args = ap.parse_args()

    in_dir = Path(args.in_dir)
    if_dir = Path(args.if_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Dane
    X_train = _load_csv(in_dir / "X_train_baseline.csv")
    X_val = _load_csv(in_dir / "X_val_baseline.csv")
    X_test = _load_csv(in_dir / "X_test.csv")
    y_test = _load_csv(in_dir / "y_test_is_anomaly.csv")["is_anomaly"].astype(int)
    meta_test = _load_csv(in_dir / "meta_test.csv")

    # Ten sam scaler co IF (ważne dla porównań)
    scaler = _load_pickle(if_dir / "scaler.pkl")
    X_train_s = scaler.transform(X_train.values)
    X_val_s = scaler.transform(X_val.values)
    X_test_s = scaler.transform(X_test.values)

    _save_pickle(scaler, out_dir / "scaler.pkl")

    # LOF (novelty=True!)
    lof = LocalOutlierFactor(
        n_neighbors=args.n_neighbors,
        novelty=True,
        metric="minkowski",
    )
    lof.fit(X_train_s)
    _save_pickle(lof, out_dir / "lof.pkl")

    # Score: im większy, tym bardziej anomalia
    val_score = -lof.score_samples(X_val_s)
    test_score = -lof.score_samples(X_test_s)

    threshold = float(np.quantile(val_score, args.quantile))
    y_pred = (test_score > threshold).astype(int)

    tp = int(((y_pred == 1) & (y_test == 1)).sum())
    tn = int(((y_pred == 0) & (y_test == 0)).sum())
    fp = int(((y_pred == 1) & (y_test == 0)).sum())
    fn = int(((y_pred == 0) & (y_test == 1)).sum())

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    report: Dict[str, Any] = {
        "model": "LOF (novelty)",
        "train_rows": int(len(X_train)),
        "val_rows": int(len(X_val)),
        "test_rows": int(len(X_test)),
        "features": int(X_train.shape[1]),
        "threshold": {"quantile": args.quantile, "value": threshold},
        "confusion": {"tp": tp, "tn": tn, "fp": fp, "fn": fn},
        "metrics": {"precision": precision, "recall": recall, "fpr": fpr},
        "params": {"n_neighbors": args.n_neighbors},
    }

    (out_dir / "lof_threshold.json").write_text(
        json.dumps(report["threshold"], indent=2), encoding="utf-8"
    )
    (out_dir / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    df_scores = pd.DataFrame(
        {
            "score": test_score,
            "y_true": y_test.values,
            "y_pred": y_pred,
            "scenario_id": meta_test["scenario_id"].values,
            "run_id": meta_test["run_id"].values,
        }
    )
    df_scores.to_csv(out_dir / "test_scores.csv", index=False)

    print("[KROK 4] OK.")
    print("  threshold:", threshold)
    print("  confusion:", report["confusion"])
    print("  metrics:", report["metrics"])
    print("  artifacts:", out_dir.resolve())

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
