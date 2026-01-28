# analysis/train_autoencoder_unsup.py
from __future__ import annotations

import argparse
import json
import pickle
from pathlib import Path
from typing import Dict, Any

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset


DEFAULT_BASE = Path("data_prepared/unsupervised")
DEFAULT_IN_DIR = DEFAULT_BASE / "step2_features"
DEFAULT_IF_DIR = DEFAULT_BASE / "step3_iforest"
DEFAULT_OUT_DIR = DEFAULT_BASE / "step5_autoencoder"


class AutoEncoder(nn.Module):
    def __init__(self, dim: int):
        super().__init__()
        bottleneck = max(4, dim // 3)
        self.net = nn.Sequential(
            nn.Linear(dim, dim),
            nn.ReLU(),
            nn.Linear(dim, bottleneck),
            nn.ReLU(),
            nn.Linear(bottleneck, dim),
        )

    def forward(self, x):
        return self.net(x)


def mse_per_sample(x, x_hat):
    return ((x - x_hat) ** 2).mean(dim=1)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--epochs", type=int, default=40)
    ap.add_argument("--batch_size", type=int, default=32)
    ap.add_argument("--lr", type=float, default=1e-3)
    ap.add_argument("--quantile", type=float, default=0.99)
    ap.add_argument("--out_dir", default=str(DEFAULT_OUT_DIR))
    args = ap.parse_args()

    in_dir = DEFAULT_IN_DIR
    if_dir = DEFAULT_IF_DIR
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Dane
    X_train = pd.read_csv(in_dir / "X_train_baseline.csv").values
    X_val = pd.read_csv(in_dir / "X_val_baseline.csv").values
    X_test = pd.read_csv(in_dir / "X_test.csv").values
    y_test = pd.read_csv(in_dir / "y_test_is_anomaly.csv")["is_anomaly"].values
    meta_test = pd.read_csv(in_dir / "meta_test.csv")

    # Scaler (ten sam co IF)
    with open(if_dir / "scaler.pkl", "rb") as f:
        scaler = pickle.load(f)

    X_train = scaler.transform(X_train)
    X_val = scaler.transform(X_val)
    X_test = scaler.transform(X_test)

    # Torch
    device = torch.device("cpu")
    dim = X_train.shape[1]
    model = AutoEncoder(dim).to(device)
    opt = torch.optim.Adam(model.parameters(), lr=args.lr)
    loss_fn = nn.MSELoss()

    train_ds = TensorDataset(torch.tensor(X_train, dtype=torch.float32))
    train_dl = DataLoader(train_ds, batch_size=args.batch_size, shuffle=True)

    # Trening
    model.train()
    for epoch in range(args.epochs):
        losses = []
        for (xb,) in train_dl:
            xb = xb.to(device)
            opt.zero_grad()
            xh = model(xb)
            loss = loss_fn(xh, xb)
            loss.backward()
            opt.step()
            losses.append(loss.item())
        if epoch % 10 == 0:
            print(f"epoch {epoch:02d} | loss={np.mean(losses):.6f}")

    torch.save(model.state_dict(), out_dir / "ae_model.pt")

    # Scoring
    model.eval()
    with torch.no_grad():
        Xv = torch.tensor(X_val, dtype=torch.float32)
        Xt = torch.tensor(X_test, dtype=torch.float32)

        val_err = mse_per_sample(Xv, model(Xv)).numpy()
        test_err = mse_per_sample(Xt, model(Xt)).numpy()

    threshold = float(np.quantile(val_err, args.quantile))
    y_pred = (test_err > threshold).astype(int)

    # Metryki
    tp = int(((y_pred == 1) & (y_test == 1)).sum())
    tn = int(((y_pred == 0) & (y_test == 0)).sum())
    fp = int(((y_pred == 1) & (y_test == 0)).sum())
    fn = int(((y_pred == 0) & (y_test == 1)).sum())

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    report: Dict[str, Any] = {
        "model": "Autoencoder",
        "epochs": args.epochs,
        "features": dim,
        "threshold": {"quantile": args.quantile, "value": threshold},
        "confusion": {"tp": tp, "tn": tn, "fp": fp, "fn": fn},
        "metrics": {"precision": precision, "recall": recall, "fpr": fpr},
    }

    (out_dir / "ae_threshold.json").write_text(
        json.dumps(report["threshold"], indent=2), encoding="utf-8"
    )
    (out_dir / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    df_scores = pd.DataFrame(
        {
            "score": test_err,
            "y_true": y_test,
            "y_pred": y_pred,
            "scenario_id": meta_test["scenario_id"],
            "run_id": meta_test["run_id"],
        }
    )
    df_scores.to_csv(out_dir / "test_scores.csv", index=False)

    print("[KROK 5] OK.")
    print("  threshold:", threshold)
    print("  confusion:", report["confusion"])
    print("  metrics:", report["metrics"])
    print("  artifacts:", out_dir.resolve())

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
