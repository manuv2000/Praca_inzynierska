# analysis/dataset_builder.py
from __future__ import annotations

import argparse
import csv
from pathlib import Path
from typing import Dict, Any, List, Tuple

import pandas as pd

LABEL_MAP = {
    "baseline": 0,
    "baseline_ro_scan": 1,
    "baseline_write_inj": 2,
    "baseline_proxy_spoof": 3,
    # jeśli dodasz mass_overwrite_only do datasetów:
    # "mass_overwrite_only": 4,
}

ANOMALY_SET = {
    "baseline_ro_scan",
    "baseline_write_inj",
    "baseline_proxy_spoof",
    # "mass_overwrite_only",
}


def project_root() -> Path:
    # analysis/dataset_builder.py -> parents[1] == projekt
    return Path(__file__).resolve().parents[1]


def resolve_under_root(p: str) -> Path:
    """Relatywne ścieżki traktuj jako względem root projektu."""
    pp = Path(p)
    return pp if pp.is_absolute() else (project_root() / pp)


def read_index_csv(index_path: Path) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    with index_path.open("r", encoding="utf-8", newline="") as f:
        r = csv.DictReader(f)
        for row in r:
            rows.append(row)
    return rows


def safe_bool(x: Any) -> bool:
    if x is None:
        return False
    s = str(x).strip().lower()
    return s in {"1", "true", "yes", "y", "ok"}


def drop_edge_windows(df: pd.DataFrame) -> pd.DataFrame:
    """Usuń pierwsze i ostatnie okno per run_id (często ucięte)."""
    if df.empty:
        return df

    out_parts = []
    for run_id, part in df.groupby("run_id", sort=False):
        if len(part) < 3:
            continue
        wmin = part["win_index"].min()
        wmax = part["win_index"].max()
        out_parts.append(part.loc[~part["win_index"].isin([wmin, wmax])])

    if not out_parts:
        return df.iloc[0:0].copy()

    out = pd.concat(out_parts, ignore_index=True)
    return out.reset_index(drop=True)


def build_dataset(
    *,
    index_csv: Path,
    out_csv: Path,
    keep_only_ok: bool = True,
    drop_edges_flag: bool = True,
) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    rows = read_index_csv(index_csv)
    if not rows:
        raise RuntimeError(f"index.csv is empty: {index_csv}")

    all_parts: List[pd.DataFrame] = []
    skipped = 0
    used = 0

    for r in rows:
        run_id = (r.get("run_id") or "").strip()
        scenario_id = (r.get("scenario_id") or "").strip()
        windows_csv = (r.get("windows_csv") or "").strip()
        ok = safe_bool(r.get("ok"))

        if keep_only_ok and not ok:
            skipped += 1
            continue
        if scenario_id not in LABEL_MAP:
            skipped += 1
            continue

        p_csv = Path(windows_csv)
        if not p_csv.is_absolute():
            # index.csv może mieć relatywne ścieżki — dopnij do root
            p_csv = project_root() / p_csv

        if not p_csv.exists():
            skipped += 1
            continue

        df = pd.read_csv(p_csv)
        if df.empty:
            skipped += 1
            continue

        df["run_id"] = run_id
        df["scenario_id"] = scenario_id
        df["y_multiclass"] = LABEL_MAP[scenario_id]
        df["is_anomaly"] = 1 if scenario_id in ANOMALY_SET else 0

        all_parts.append(df)
        used += 1

    if not all_parts:
        raise RuntimeError("No usable runs found from index.csv")

    out = pd.concat(all_parts, ignore_index=True)

    # typy
    out["win_index"] = pd.to_numeric(out["win_index"], errors="coerce").fillna(-1).astype(int)

    if drop_edges_flag:
        out = drop_edge_windows(out)

    out_csv.parent.mkdir(parents=True, exist_ok=True)
    out.to_csv(out_csv, index=False, encoding="utf-8")

    stats = {
        "index_rows": len(rows),
        "runs_used": used,
        "runs_skipped": skipped,
        "dataset_rows": len(out),
        "columns": list(out.columns),
        "out_csv": str(out_csv),
    }
    return out, stats


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--index", default="capture/pcap/index.csv", help="Ścieżka do index.csv")
    ap.add_argument("--out", default="capture/pcap/datasets/windows_5s.csv", help="Wyjściowy dataset CSV")
    ap.add_argument("--keep-only-ok", action="store_true", help="Używaj tylko ok=True z index.csv")
    ap.add_argument("--no-drop-edges", action="store_true", help="Nie usuwaj pierwszego/ostatniego okna per run")
    args = ap.parse_args()

    index_csv = resolve_under_root(args.index)
    out_csv = resolve_under_root(args.out)

    df, stats = build_dataset(
        index_csv=index_csv,
        out_csv=out_csv,
        keep_only_ok=bool(args.keep_only_ok),
        drop_edges_flag=not bool(args.no_drop_edges),
    )

    print("[OK] Dataset built.")
    print("  out:", stats["out_csv"])
    print("  rows:", stats["dataset_rows"])
    print("  runs_used:", stats["runs_used"], "runs_skipped:", stats["runs_skipped"])
    print("  columns:", len(stats["columns"]))


if __name__ == "__main__":
    main()
