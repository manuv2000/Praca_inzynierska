import json, pandas as pd, numpy as np
from datetime import datetime

def load_json_lines(path):
    rows=[]
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            try:
                rec = json.loads(line)
                # wyciągnij pola wg tshark JSON (może wymagać dostosowania)
                layers = rec["_source"]["layers"]
                t = float(layers["frame.time_epoch"][0])
                src = layers.get("ip.src", [""])[0]
                sport = int(layers.get("tcp.srcport", ["0"])[0])
                dst = layers.get("ip.dst", [""])[0]
                dport = int(layers.get("tcp.dstport", ["0"])[0])
                fc = int(layers.get("modbus.func_code", ["-1"])[0]) if "modbus.func_code" in layers else -1
                addr = int(layers.get("modbus.reference_num", ["-1"])[0]) if "modbus.reference_num" in layers else -1
                exc = int(layers.get("modbus.exception_code", ["0"])[0]) if "modbus.exception_code" in layers else 0
                size = int(layers.get("frame.len", ["0"])[0])
                rows.append({"ts": t,"src":src,"sport":sport,"dst":dst,"dport":dport,
                             "fc":fc,"addr":addr,"exc":exc,"len":size})
            except: pass
    return pd.DataFrame(rows)

def window_features(df, window_s=1):
    df["ts_bin"] = (df["ts"] // window_s).astype(int)
    grp = df.groupby(["src","dst","ts_bin"])
    feats = grp.agg(
        pkts=("fc","count"),
        fc1=("fc", lambda x:(x==1).sum()),
        fc3=("fc", lambda x:(x==3).sum()),
        fc5=("fc", lambda x:(x==5).sum()),
        fc6=("fc", lambda x:(x==6).sum()),
        fc15=("fc", lambda x:(x==15).sum()),
        fc16=("fc", lambda x:(x==16).sum()),
        exc_cnt=("exc", lambda x:(x>0).sum()),
        addr_min=("addr","min"),
        addr_max=("addr","max"),
        size_avg=("len","mean")
    ).reset_index()
    feats["ts_start"] = feats["ts_bin"]*window_s
    return feats
