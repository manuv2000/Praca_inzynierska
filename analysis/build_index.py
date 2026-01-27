import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAN_DIR = ROOT / "capture" / "pcap" / "manifests"
FEAT_DIR = ROOT / "capture" / "pcap" / "features"
OUT = ROOT / "capture" / "pcap" / "index.csv"

def main():
    MAN_DIR.mkdir(parents=True, exist_ok=True)
    FEAT_DIR.mkdir(parents=True, exist_ok=True)

    rows = []
    for mf in sorted(MAN_DIR.glob("*.manifest.json")):
        data = json.loads(mf.read_text(encoding="utf-8"))
        run_id = data.get("run_id")
        scenario_id = data.get("scenario_id")
        ok = data.get("result", {}).get("ok")
        pcap_main = data.get("capture", {}).get("pcap_main")

        # zakładamy konwencję nazw features: <run_id>.win5s.csv (możesz ją wprowadzić później)
        # na teraz szukamy po run_id w nazwie
        win_csv = None
        rep_json = None
        if run_id:
            candidates = list(FEAT_DIR.glob(f"*{run_id}*.win*.csv"))
            if candidates:
                win_csv = str(candidates[0])
                rep = Path(str(candidates[0]) + ".report.json")
                if rep.exists():
                    rep_json = str(rep)

        rows.append({
            "run_id": run_id,
            "scenario_id": scenario_id,
            "manifest": str(mf),
            "pcap_main": pcap_main,
            "windows_csv": win_csv,
            "windows_report": rep_json,
            "ok": ok,
        })

    with OUT.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ["run_id"])
        w.writeheader()
        w.writerows(rows)

    print(f"index saved: {OUT} (rows={len(rows)})")

if __name__ == "__main__":
    main()
