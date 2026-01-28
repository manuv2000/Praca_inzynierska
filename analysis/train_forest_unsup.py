# analysis/train_iforest_unsup.py
from __future__ import annotations

import argparse
import json
import pickle
from pathlib import Path
from typing import Dict, Any

import numpy as np
import pandas as pd
from sklearn.preprocessing import RobustScaler
from sklearn.ensemble import IsolationForest


DEFAULT_BASE = Path("data_prepared/unsupervised")
DEFAULT_IN_DIR = DEFAULT_BASE / "step2_features"
DEFAULT_OUT_DIR = DEFAULT_BASE / "step3_iforest"


def _load_csv(path: Path) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(f"Brak pliku: {path}")
    return pd.read_csv(path)


def _save_pickle(obj: object, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        pickle.dump(obj, f)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in_dir", default=str(DEFAULT_IN_DIR))
    ap.add_argument("--out_dir", default=str(DEFAULT_OUT_DIR))
    ap.add_argument("--quantile", type=float, default=0.99, help="percentyl na threshold z VAL baseline (np. 0.99)")
    ap.add_argument("--n_estimators", type=int, default=200)
    ap.add_argument("--max_samples", default="auto")
    ap.add_argument("--contamination", default="auto", help='"auto" albo np. 0.05')
    ap.add_argument("--random_state", type=int, default=42)
    args = ap.parse_args()

    in_dir = Path(args.in_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Wejścia z kroku 2
    X_train = _load_csv(in_dir / "X_train_baseline.csv")
    X_val = _load_csv(in_dir / "X_val_baseline.csv")
    X_test = _load_csv(in_dir / "X_test.csv")
    y_test = _load_csv(in_dir / "y_test_is_anomaly.csv")["is_anomaly"].astype(int)

    meta_test = _load_csv(in_dir / "meta_test.csv")  # run_id, scenario_id

    # 1) RobustScaler fit tylko na TRAIN baseline
    scaler = RobustScaler()
    X_train_s = scaler.fit_transform(X_train.values)
    X_val_s = scaler.transform(X_val.values)
    X_test_s = scaler.transform(X_test.values)

    _save_pickle(scaler, out_dir / "scaler.pkl")

    # 2) Isolation Forest fit tylko na TRAIN baseline
    model = IsolationForest(
        n_estimators=args.n_estimators,
        max_samples=args.max_samples,
        contamination=args.contamination,
        random_state=args.random_state,
        n_jobs=-1,
    )
    model.fit(X_train_s)
    _save_pickle(model, out_dir / "iforest.pkl")

    # 3) Skoring: bierzemy "anomaly score" jako -decision_function (im większy, tym bardziej anomalia)
    # decision_function: większe = bardziej normalne, mniejsze = bardziej anomalia
    val_dec = model.decision_function(X_val_s)
    test_dec = model.decision_function(X_test_s)

    val_score = -val_dec
    test_score = -test_dec

    # 4) Threshold z VAL baseline (np. 99 percentyl)
    q = float(args.quantile)
    threshold = float(np.quantile(val_score, q))

    # 5) Predykcja na teście
    y_pred = (test_score > threshold).astype(int)

    # 6) Raport metryk (szybki, bez wodotrysków)
    tp = int(((y_pred == 1) & (y_test == 1)).sum())
    tn = int(((y_pred == 0) & (y_test == 0)).sum())
    fp = int(((y_pred == 1) & (y_test == 0)).sum())
    fn = int(((y_pred == 0) & (y_test == 1)).sum())

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    report: Dict[str, Any] = {
        "model": "IsolationForest",
        "scaler": "RobustScaler",
        "train_rows": int(len(X_train)),
        "val_rows": int(len(X_val)),
        "test_rows": int(len(X_test)),
        "features": int(X_train.shape[1]),
        "threshold": {"quantile": q, "value": threshold},
        "confusion": {"tp": tp, "tn": tn, "fp": fp, "fn": fn},
        "metrics": {"precision": precision, "recall": recall, "fpr": fpr},
        "params": {
            "n_estimators": args.n_estimators,
            "max_samples": args.max_samples,
            "contamination": args.contamination,
            "random_state": args.random_state,
        },
    }

    (out_dir / "iforest_threshold.json").write_text(
        json.dumps(report["threshold"], indent=2), encoding="utf-8"
    )
    (out_dir / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    # 7) Zapis score na teście (pod dalsze wykresy/porównania modeli)
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

    print("[KROK 3] OK.")
    print("  threshold:", threshold, f"(quantile={q})")
    print("  confusion:", report["confusion"])
    print("  metrics:", report["metrics"])
    print("  artifacts:", out_dir.resolve())

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
