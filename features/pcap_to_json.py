import subprocess, glob, json, sys

FIELDS = [
  "_ws.col.Time", "frame.time_epoch",
  "ip.src", "tcp.srcport", "ip.dst", "tcp.dstport",
  "modbus.func_code", "modbus.reference_num", "modbus.word_cnt", "modbus.exception_code",
  "frame.len"
]

def pcap_to_json(pcap_path, out_path):
    cmd = ["tshark", "-r", pcap_path, "-Y", "tcp.port==502",
           "-T", "json", "-e"] + [f for pair in FIELDS for f in ["-e", f]] + ["-E", "aggregated=true", "-E", "separator=,"]

    # tshark -T json wypisuje jeden wielki JSON; uprościmy do newline-JSON
    raw = subprocess.check_output(cmd)
    arr = json.loads(raw)
    with open(out_path, "w", encoding="utf-8") as f:
        for pkt in arr:
            f.write(json.dumps(pkt, ensure_ascii=False) + "\n")

if __name__ == "__main__":
    pcap = sys.argv[1]
    out = sys.argv[2]
    pcap_to_json(pcap, out)
