# analysis/prepare_unsup_dataset.py
from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from typing import List, Dict, Tuple

import pandas as pd


DEFAULT_INPUT_DIR = Path("capture/pcap/datasets")
DEFAULT_PREFIX = "windows_5s"
DEFAULT_OUT_DIR = Path("data_prepared/unsupervised")


# Kolumny, które NA PEWNO nie mogą wejść do X (meta/etykiety/identyfikatory)
DROP_ALWAYS = {
    "run_id",
    "scenario_id",
    "y_multiclass",
    "is_anomaly",
}

# Kolumny "czasowe/okienne" — w praktyce w ICS często lepiej je wyrzucić,
# żeby model nie uczył się pozycji w runie.
DROP_TIME = {
    "win_index",
    "t_start",
    "t_end",
}

# Jeśli chcesz je zostawić jako cechy, uruchom skrypt z --keep_time_cols


def _copy_file(src: Path, dst: Path, force: bool) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists() and not force:
        return
    shutil.copy2(src, dst)


def step1_copy_raw(input_dir: Path, prefix: str, out_dir: Path, force: bool) -> Dict[str, str]:
    """
    KROK 1:
    Kopiuje źródłowe CSV do data_prepared/unsupervised/raw/ bez ruszania oryginałów.
    """
    raw_dir = out_dir / "raw"
    files = {
        "all": input_dir / f"{prefix}.csv",
        "train": input_dir / f"{prefix}.train.csv",
        "val": input_dir / f"{prefix}.val.csv",
        "test": input_dir / f"{prefix}.test.csv",
    }

    missing = [k for k, p in files.items() if not p.exists()]
    if missing:
        raise FileNotFoundError(
            f"Brakuje plików: {missing}. Spodziewałem się ich w: {input_dir.resolve()}"
        )

    copied = {}
    for k, src in files.items():
        dst = raw_dir / src.name
        _copy_file(src, dst, force=force)
        copied[k] = str(dst)
    return copied


def _infer_feature_columns(df: pd.DataFrame, keep_time_cols: bool) -> List[str]:
    drop = set(DROP_ALWAYS)
    if not keep_time_cols:
        drop |= set(DROP_TIME)

    # Zostawiamy tylko kolumny numeryczne poza drop-listą
    candidate_cols = [c for c in df.columns if c not in drop]

    # Wymuszamy numeryczne – jeśli coś nie jest numeryczne, odrzucimy to
    numeric_cols = []
    for c in candidate_cols:
        if pd.api.types.is_numeric_dtype(df[c]):
            numeric_cols.append(c)
        else:
            # Spróbuj skonwertować w locie (np. "1.23" jako string)
            coerced = pd.to_numeric(df[c], errors="coerce")
            if coerced.notna().any():
                numeric_cols.append(c)
            # inaczej: odrzucamy (meta/string)
    return numeric_cols


def _to_numeric_frame(df: pd.DataFrame, cols: List[str]) -> pd.DataFrame:
    out = df[cols].copy()
    for c in cols:
        out[c] = pd.to_numeric(out[c], errors="coerce")
    return out


def step2_build_X(
    raw_dir: Path,
    prefix: str,
    out_dir: Path,
    keep_time_cols: bool,
) -> Dict[str, str]:
    """
    KROK 2:
    - TRAIN: tylko baseline
    - VAL: tylko baseline
    - TEST: mieszany (baseline + ataki)
    Buduje czyste X i zapisuje artefakty.
    """
    train_path = raw_dir / f"{prefix}.train.csv"
    val_path = raw_dir / f"{prefix}.val.csv"
    test_path = raw_dir / f"{prefix}.test.csv"

    df_train = pd.read_csv(train_path)
    df_val = pd.read_csv(val_path)
    df_test = pd.read_csv(test_path)

    # Filtry unsupervised
    df_train_b = df_train[df_train["scenario_id"] == "baseline"].copy()
    df_val_b = df_val[df_val["scenario_id"] == "baseline"].copy()
    df_test_all = df_test.copy()

    if df_train_b.empty:
        raise ValueError("TRAIN baseline jest pusty. Sprawdź scenario_id i split.")
    if df_val_b.empty:
        raise ValueError("VAL baseline jest pusty. Sprawdź scenario_id i split.")
    if df_test_all.empty:
        raise ValueError("TEST jest pusty. Sprawdź pliki wejściowe.")

    # Kolumny cech wyznaczamy z TRAIN baseline (żeby było deterministycznie)
    feature_cols = _infer_feature_columns(df_train_b, keep_time_cols=keep_time_cols)
    if not feature_cols:
        raise ValueError("Nie udało się wyznaczyć żadnych kolumn cech numerycznych dla X.")

    X_train = _to_numeric_frame(df_train_b, feature_cols)
    X_val = _to_numeric_frame(df_val_b, feature_cols)
    X_test = _to_numeric_frame(df_test_all, feature_cols)

    # Minimalny sanity: NaN w cechach – zapisujemy info, ale nie naprawiamy jeszcze (to będzie krok skalowania/clean)
    nan_report = {
        "train_nan_cells": int(X_train.isna().sum().sum()),
        "val_nan_cells": int(X_val.isna().sum().sum()),
        "test_nan_cells": int(X_test.isna().sum().sum()),
    }

    out_step2 = out_dir / "step2_features"
    out_step2.mkdir(parents=True, exist_ok=True)

    paths = {}

    # Zapis X
    p = out_step2 / "X_train_baseline.csv"
    X_train.to_csv(p, index=False)
    paths["X_train_baseline"] = str(p)

    p = out_step2 / "X_val_baseline.csv"
    X_val.to_csv(p, index=False)
    paths["X_val_baseline"] = str(p)

    p = out_step2 / "X_test.csv"
    X_test.to_csv(p, index=False)
    paths["X_test"] = str(p)

    # Etykiety testowe (tylko ewaluacja)
    if "is_anomaly" not in df_test_all.columns:
        raise ValueError("Brak kolumny is_anomaly w teście – potrzebna do ewaluacji (nawet jeśli unsupervised).")

    y_test = df_test_all["is_anomaly"].astype(int)
    p = out_step2 / "y_test_is_anomaly.csv"
    y_test.to_csv(p, index=False, header=True)
    paths["y_test_is_anomaly"] = str(p)

    # Meta do raportów (opcjonalnie, ale bardzo przydatne)
    meta = df_test_all[["run_id", "scenario_id"]].copy()
    p = out_step2 / "meta_test.csv"
    meta.to_csv(p, index=False)
    paths["meta_test"] = str(p)

    # Lista cech (kolejność!)
    p = out_step2 / "features.json"
    p.write_text(json.dumps({"features": feature_cols, "keep_time_cols": keep_time_cols}, indent=2), encoding="utf-8")
    paths["features"] = str(p)

    # Manifest (liczności i sanity)
    manifest = {
        "counts": {
            "train_rows_total": int(len(df_train)),
            "val_rows_total": int(len(df_val)),
            "test_rows_total": int(len(df_test_all)),
            "train_baseline_rows": int(len(df_train_b)),
            "val_baseline_rows": int(len(df_val_b)),
        },
        "scenario_dist_test": df_test_all["scenario_id"].value_counts().to_dict(),
        "feature_count": int(len(feature_cols)),
        "nan_report": nan_report,
        "source_files": {
            "train": str(train_path),
            "val": str(val_path),
            "test": str(test_path),
        },
    }
    p = out_step2 / "manifest.json"
    p.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    paths["manifest"] = str(p)

    return paths


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input_dir", default=str(DEFAULT_INPUT_DIR), help="np. capture/pcap/datasets")
    ap.add_argument("--prefix", default=DEFAULT_PREFIX, help="np. windows_5s")
    ap.add_argument("--out_dir", default=str(DEFAULT_OUT_DIR), help="np. data_prepared/unsupervised")
    ap.add_argument("--force", action="store_true", help="nadpisz kopie w out_dir/raw jeśli istnieją")
    ap.add_argument("--keep_time_cols", action="store_true", help="zostaw win_index/t_start/t_end jako cechy")
    args = ap.parse_args()

    input_dir = Path(args.input_dir)
    out_dir = Path(args.out_dir)
    prefix = args.prefix

    copied = step1_copy_raw(input_dir=input_dir, prefix=prefix, out_dir=out_dir, force=args.force)
    print("[KROK 1] OK. Skopiowano pliki do:", out_dir / "raw")
    for k, v in copied.items():
        print(f"  - {k}: {v}")

    paths = step2_build_X(raw_dir=out_dir / "raw", prefix=prefix, out_dir=out_dir, keep_time_cols=args.keep_time_cols)
    print("\n[KROK 2] OK. Zapisano artefakty do:", out_dir / "step2_features")
    for k, v in paths.items():
        print(f"  - {k}: {v}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
