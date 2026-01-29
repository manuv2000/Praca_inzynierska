# analysis/plot_unsup_results.py
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, Any, Tuple, List

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.metrics import (
    precision_score,
    recall_score,
    confusion_matrix,
    roc_curve,
    auc,
    precision_recall_curve,
    average_precision_score,
)


def project_root() -> Path:
    # analysis/plot_unsup_results.py -> parents[1] == root projektu
    return Path(__file__).resolve().parents[1]


def load_report(step_dir: Path) -> Dict[str, Any]:
    p = step_dir / "report.json"
    if not p.exists():
        return {}
    return json.loads(p.read_text(encoding="utf-8"))


def load_scores(step_dir: Path) -> pd.DataFrame:
    p = step_dir / "test_scores.csv"
    if not p.exists():
        raise FileNotFoundError(f"Brak: {p}")
    df = pd.read_csv(p)

    # wymagane kolumny wg Twojego formatu
    required = {"score", "y_true", "y_pred", "scenario_id", "run_id"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"{p} nie ma kolumn: {sorted(missing)}")

    # typy
    df["y_true"] = df["y_true"].astype(int)
    df["y_pred"] = df["y_pred"].astype(int)
    df["score"] = pd.to_numeric(df["score"], errors="coerce")
    df = df.dropna(subset=["score"]).copy()

    return df


def compute_metrics(df: pd.DataFrame) -> Dict[str, float]:
    y_true = df["y_true"].to_numpy()
    y_pred = df["y_pred"].to_numpy()

    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec = float(recall_score(y_true, y_pred, zero_division=0))
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    fpr = float(fp / (fp + tn)) if (fp + tn) else 0.0

    return {"precision": prec, "recall": rec, "fpr": fpr, "tp": tp, "tn": tn, "fp": fp, "fn": fn}


def safe_model_name(step_dir: Path) -> str:
    name = step_dir.name.lower()
    if "iforest" in name:
        return "IsolationForest"
    if "lof" in name:
        return "LOF"
    if "autoencoder" in name:
        return "Autoencoder"
    return step_dir.name


def normalize_scores_for_plot(scores: np.ndarray) -> np.ndarray:
    """
    Normalizacja tylko do wykresów porównawczych, bo skale score są skrajnie różne (LOF/AE potrafią mieć giganty).
    Robimy robust: dzielimy przez percentyl 95 + obcinamy.
    """
    q = np.quantile(scores, 0.95) if len(scores) else 1.0
    q = float(q) if q and np.isfinite(q) else 1.0
    out = scores / q
    out = np.clip(out, 0.0, 5.0)
    return out


def plot_bar_metrics(metrics_by_model: Dict[str, Dict[str, float]], out_dir: Path) -> Path:
    models = list(metrics_by_model.keys())
    precision = [metrics_by_model[m]["precision"] for m in models]
    recall = [metrics_by_model[m]["recall"] for m in models]
    fpr = [metrics_by_model[m]["fpr"] for m in models]

    x = np.arange(len(models))
    w = 0.25

    plt.figure()
    plt.title("Porównanie modeli (test) — metryki decyzyjne")
    plt.xticks(x, models, rotation=0)

    plt.bar(x - w, precision, width=w, label="precision")
    plt.bar(x, recall, width=w, label="recall")
    plt.bar(x + w, fpr, width=w, label="FPR")

    plt.ylim(0, 1.0)
    plt.ylabel("wartość")
    plt.grid(True, axis="y", linestyle="--", linewidth=0.5)
    plt.legend()

    out_path = out_dir / "cmp_metrics_bar.png"
    plt.tight_layout()
    plt.savefig(out_path, dpi=200)
    plt.close()
    return out_path


def plot_roc(models_data: Dict[str, pd.DataFrame], out_dir: Path) -> Path:
    plt.figure()
    plt.title("ROC (test) — porównanie modeli")
    plt.xlabel("FPR")
    plt.ylabel("TPR")

    for model, df in models_data.items():
        y_true = df["y_true"].to_numpy()
        score = df["score"].to_numpy()

        # Uwaga: score ma różne skale, ale ROC i tak działa na porządku score.
        fpr, tpr, _ = roc_curve(y_true, score)
        roc_auc = auc(fpr, tpr)
        plt.plot(fpr, tpr, label=f"{model} (AUC={roc_auc:.3f})")

    plt.plot([0, 1], [0, 1], linestyle="--")
    plt.grid(True, linestyle="--", linewidth=0.5)
    plt.legend()

    out_path = out_dir / "cmp_roc.png"
    plt.tight_layout()
    plt.savefig(out_path, dpi=200)
    plt.close()
    return out_path


def plot_pr(models_data: Dict[str, pd.DataFrame], out_dir: Path) -> Path:
    plt.figure()
    plt.title("Precision–Recall (test) — porównanie modeli")
    plt.xlabel("Recall")
    plt.ylabel("Precision")

    for model, df in models_data.items():
        y_true = df["y_true"].to_numpy()
        score = df["score"].to_numpy()

        prec, rec, _ = precision_recall_curve(y_true, score)
        ap = average_precision_score(y_true, score)
        plt.plot(rec, prec, label=f"{model} (AP={ap:.3f})")

    plt.grid(True, linestyle="--", linewidth=0.5)
    plt.legend()

    out_path = out_dir / "cmp_pr.png"
    plt.tight_layout()
    plt.savefig(out_path, dpi=200)
    plt.close()
    return out_path


def plot_score_distributions(models_data: Dict[str, pd.DataFrame], out_dir: Path) -> Path:
    plt.figure()
    plt.title("Rozkład score (test) — baseline vs anomaly ")
    plt.xlabel("score_norm")
    plt.ylabel("liczność")

    for model, df in models_data.items():
        score = df["score"].to_numpy()
        y = df["y_true"].to_numpy()

        score_n = normalize_scores_for_plot(score)

        s0 = score_n[y == 0]
        s1 = score_n[y == 1]

        plt.hist(s0, bins=30, alpha=0.35, label=f"{model} baseline (y=0)")
        plt.hist(s1, bins=30, alpha=0.35, label=f"{model} anomaly (y=1)")

    plt.grid(True, linestyle="--", linewidth=0.5)
    plt.legend()

    out_path = out_dir / "cmp_score_distributions.png"
    plt.tight_layout()
    plt.savefig(out_path, dpi=200)
    plt.close()
    return out_path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--base",
        default=str(project_root() / "data_prepared" / "unsupervised"),
        help="np. data_prepared/unsupervised",
    )
    ap.add_argument(
        "--out",
        default=str(project_root() / "analysis" / "plots_unsup"),
        help="katalog wyjściowy na wykresy",
    )
    args = ap.parse_args()

    base = Path(args.base)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    steps = [
        base / "step3_iforest",
        base / "step4_lof",
        base / "step5_autoencoder",
    ]

    models_data: Dict[str, pd.DataFrame] = {}
    metrics_by_model: Dict[str, Dict[str, float]] = {}

    # Wczytanie danych
    for step in steps:
        if not step.exists():
            print("[WARN] brak katalogu:", step)
            continue
        df = load_scores(step)
        model = safe_model_name(step)
        models_data[model] = df
        metrics_by_model[model] = compute_metrics(df)

    if not models_data:
        raise RuntimeError(f"Nie znaleziono żadnych danych test_scores.csv w: {base}")

    # Zapis tabelki tekstowej (technicznie, pod rozdział wyników)
    rows = []
    for m, met in metrics_by_model.items():
        rows.append(
            {
                "model": m,
                "precision": met["precision"],
                "recall": met["recall"],
                "fpr": met["fpr"],
                "tp": met["tp"],
                "tn": met["tn"],
                "fp": met["fp"],
                "fn": met["fn"],
            }
        )
    df_tab = pd.DataFrame(rows).sort_values("model")
    tab_path = out_dir / "cmp_metrics_table.csv"
    df_tab.to_csv(tab_path, index=False)

    # Wykresy
    p1 = plot_bar_metrics(metrics_by_model, out_dir)
    p2 = plot_roc(models_data, out_dir)
    p3 = plot_pr(models_data, out_dir)
    p4 = plot_score_distributions(models_data, out_dir)

    print("[OK] zapisano:")
    print(" -", tab_path)
    print(" -", p1)
    print(" -", p2)
    print(" -", p3)
    print(" -", p4)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
