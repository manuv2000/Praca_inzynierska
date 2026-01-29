import json, pickle
from pathlib import Path
from typing import Dict, Any, List
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

class Detector:
    def __init__(self, artifacts_dir: Path):
        self.dir = artifacts_dir

        feat_payload = json.loads((self.dir / "features.json").read_text(encoding="utf-8"))
        self.features: List[str] = feat_payload["features"] if isinstance(feat_payload, dict) else feat_payload

        with open(self.dir / "scaler.pkl", "rb") as f:
            self.scaler = pickle.load(f)

        # IF (opcjonalny)
        self.iforest = None
        self.if_thr = None
        if (self.dir / "iforest.pkl").exists():
            with open(self.dir / "iforest.pkl", "rb") as f:
                self.iforest = pickle.load(f)
            self.if_thr = json.loads((self.dir / "iforest_threshold.json").read_text(encoding="utf-8"))["value"]

        # AE (opcjonalny)
        self.ae = None
        self.ae_thr = None
        if (self.dir / "ae_model.pt").exists():
            self.ae_thr = json.loads((self.dir / "ae_threshold.json").read_text(encoding="utf-8"))["value"]
            self.ae = AutoEncoder(dim=len(self.features))
            self.ae.load_state_dict(torch.load(self.dir / "ae_model.pt", map_location="cpu"))
            self.ae.eval()

    def _vectorize(self, feat_dict: Dict[str, float]) -> np.ndarray:
        return np.array([float(feat_dict.get(k, 0.0)) for k in self.features], dtype=np.float32)[None, :]

    def score(self, feat_dict: Dict[str, float]) -> Dict[str, Any]:
        x = self._vectorize(feat_dict)
        xs = self.scaler.transform(x)

        out: Dict[str, Any] = {"decision": {}}

        if self.iforest is not None:
            if_score = float(-self.iforest.decision_function(xs)[0])
            if_anom = bool(if_score > float(self.if_thr))
            out["iforest"] = {"score": if_score, "threshold": float(self.if_thr), "is_anomaly": if_anom}
        else:
            if_anom = False

        if self.ae is not None:
            xt = torch.tensor(xs, dtype=torch.float32)
            with torch.no_grad():
                xh = self.ae(xt).numpy()
            ae_score = float(((xs - xh) ** 2).mean())
            ae_anom = bool(ae_score > float(self.ae_thr))
            out["autoencoder"] = {"score": ae_score, "threshold": float(self.ae_thr), "is_anomaly": ae_anom}
        else:
            ae_anom = False

        # 2-poziomowo:
        out["decision"] = {
            "warning": bool(ae_anom),
            "critical": bool(if_anom),
            "is_anomaly": bool(ae_anom or if_anom),
        }
        return out
