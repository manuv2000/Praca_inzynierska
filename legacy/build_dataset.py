import json, sys
from feature_modbus import load_json_lines, window_features

PCAP_JSON = "capture/pcap_json.jsonl"
EVENTS = "scenarios/events.json"

if __name__ == "__main__":
    df = load_json_lines(PCAP_JSON)
    X = window_features(df, window_s=1)

    events = json.load(open(EVENTS))
    def label_row(t):
        for e in events:
            if e["end"] is None:  # baseline – ignorujemy, będzie 'normal'
                continue
            if e["start"] <= t < e["end"]:
                return e["label"]
        return "normal"

    X["label"] = X["ts_start"].apply(label_row)
    X.to_parquet("data/features.parquet")
    print("Saved data/features.parquet")
