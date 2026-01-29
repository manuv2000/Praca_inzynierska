import json, pickle
from pathlib import Path
from typing import Dict, Any, Tuple, Optional, List
import numpy as np
import torch
import torch.nn as nn

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
    def forward(self, x): return self.net(x)

def mse_per_sample(x, x_hat):
    return ((x - x_hat) ** 2).mean(axis=1)

class DetectorPipeline:
    def __init__(self, artifacts_dir: Path):
        self.artifacts_dir = artifacts_dir

        feat = json.loads((artifacts_dir / "features.json").read_text(encoding="utf-8"))
        self.features: List[str] = feat["features"]

        with open(artifacts_dir / "scaler.pkl", "rb") as f:
            self.scaler = pickle.load(f)

        with open(artifacts_dir / "iforest.pkl", "rb") as f:
            self.iforest = pickle.load(f)
        self.if_thr = json.loads((artifacts_dir / "iforest_threshold.json").read_text(encoding="utf-8"))["value"]

        # AE optional
        self.ae = None
        ae_path = artifacts_dir / "ae_model.pt"
        thr_path = artifacts_dir / "ae_threshold.json"
        if ae_path.exists() and thr_path.exists():
            self.ae_thr = json.loads(thr_path.read_text(encoding="utf-8"))["value"]
            self.ae = AutoEncoder(dim=len(self.features))
            self.ae.load_state_dict(torch.load(ae_path, map_location="cpu"))
            self.ae.eval()

    def _vectorize(self, feat_dict: Dict[str, float]) -> np.ndarray:
        return np.array([float(feat_dict.get(k, 0.0)) for k in self.features], dtype=np.float32)[None, :]

    def score(self, feat_dict: Dict[str, float]) -> Dict[str, Any]:
        x = self._vectorize(feat_dict)
        x_s = self.scaler.transform(x)

        # IF score: anomaly_score = -decision_function
        if_dec = float(self.iforest.decision_function(x_s)[0])
        if_score = float(-if_dec)
        if_anom = bool(if_score > self.if_thr)

        out = {
            "iforest": {"score": if_score, "threshold": self.if_thr, "is_anomaly": if_anom},
        }

        if self.ae is not None:
            xt = torch.tensor(x_s, dtype=torch.float32)
            with torch.no_grad():
                xh = self.ae(xt).numpy()
            ae_score = float(((x_s - xh) ** 2).mean())
            ae_anom = bool(ae_score > self.ae_thr)
            out["autoencoder"] = {"score": ae_score, "threshold": self.ae_thr, "is_anomaly": ae_anom}

            # Ensemble 2-level
            out["decision"] = {
                "warning": ae_anom,
                "critical": if_anom,
                "is_anomaly": bool(ae_anom or if_anom),
            }
        else:
            out["decision"] = {"is_anomaly": if_anom, "critical": if_anom}

        return out
