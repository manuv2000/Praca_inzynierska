from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "capture" / "pcap" / "datasets" / "windows_5s.csv"
OUT_DIR = ROOT / "capture" / "pcap" / "datasets"

TRAIN_FRAC = 0.70
VAL_FRAC   = 0.15
TEST_FRAC  = 0.15

RANDOM_SEED = 123

def main():
    df = pd.read_csv(SRC)
    required = {"run_id", "scenario_id", "win_index"}
    missing = required - set(df.columns)
    if missing:
        raise RuntimeError(f"Missing columns: {missing}")

    # sanity: duplikaty identyfikatora okna
    if df.duplicated(subset=["run_id", "win_index"]).any():
        print("[WARN] duplicates on (run_id, win_index) exist — check pipeline")

    runs = df[["run_id", "scenario_id"]].drop_duplicates().reset_index(drop=True)

    # stratified split po scenario_id (multiclass)
    splits = []
    for scenario_id, part in runs.groupby("scenario_id", sort=False):
        part = part.sample(frac=1.0, random_state=RANDOM_SEED).reset_index(drop=True)
        n = len(part)
        n_train = int(round(n * TRAIN_FRAC))
        n_val = int(round(n * VAL_FRAC))
        n_test = n - n_train - n_val

        train_ids = set(part.iloc[:n_train]["run_id"])
        val_ids   = set(part.iloc[n_train:n_train+n_val]["run_id"])
        test_ids  = set(part.iloc[n_train+n_val:]["run_id"])

        splits.append((train_ids, val_ids, test_ids))

    train = set().union(*[s[0] for s in splits])
    val   = set().union(*[s[1] for s in splits])
    test  = set().union(*[s[2] for s in splits])

    # sanity: rozłączne
    assert train.isdisjoint(val)
    assert train.isdisjoint(test)
    assert val.isdisjoint(test)

    df_train = df[df["run_id"].isin(train)].copy()
    df_val   = df[df["run_id"].isin(val)].copy()
    df_test  = df[df["run_id"].isin(test)].copy()

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    df_train.to_csv(OUT_DIR / "windows_5s.train.csv", index=False, encoding="utf-8")
    df_val.to_csv(OUT_DIR / "windows_5s.val.csv", index=False, encoding="utf-8")
    df_test.to_csv(OUT_DIR / "windows_5s.test.csv", index=False, encoding="utf-8")

    print("[OK] split done")
    print("runs:", len(runs), "train/val/test:", len(train), len(val), len(test))
    print("rows:", len(df_train), len(df_val), len(df_test))
    print("class dist (runs):")
    print(runs.assign(split=runs["run_id"].map(lambda x: "train" if x in train else "val" if x in val else "test"))
              .groupby(["split", "scenario_id"]).size())

if __name__ == "__main__":
    main()
