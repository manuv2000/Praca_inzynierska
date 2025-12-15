# PLC Security Simulation & Runtime Pipeline

This project implements a **Modbus/TCP PLC network simulation framework** designed for **unsupervised anomaly detection research**.  
It focuses on realistic traffic generation, controlled attack injection, and a clean runtime pipeline enabling later integration with **Node-RED**, **InfluxDB**, and **ML models**.

---

## 1. Simulation & Traffic Generation

### Architecture Overview

The simulation reproduces a realistic PLC environment consisting of:

- **PLC (OpenPLC runtime)** – listening on port `502`
- **HMI Master** – periodic read traffic
- **Normal Client** – read + probabilistic write traffic
- **Attack Modules** – controlled deviations from baseline
- **Optional TCP Proxy (`1502`)** – enables spoofing & replay-style attacks
- **Packet Capture (`dumpcap`)** – lossless traffic recording

All components are **decoupled and configurable**, enabling reproducible experiments.

### Implemented Scenarios

Scenarios are started via:

```bash
python -m injector.tools.attacks_menu
```

Available modes:

| Mode            | Description                                   |
|-----------------|-----------------------------------------------|
| Baseline        | HMI + normal client only                      |
| Read-only scan  | High-frequency FC3 scanning                  |
| Write injection | Targeted FC6 writes                          |
| Mass overwrite  | Rapid multi-register writes                  |
| Proxy spoofing  | Transparent MITM on port `1502`              |

Proxy spoofing introduces **real network-level anomalies** without modifying the PLC state directly.

### Key Files (Simulation)

```
injector/
├── attacks/
│   ├── modbus_proxy_spoof.py
│   ├── write_injection.py
│   ├── scan_readonly.py
│   └── mass_overwrite.py
├── traffic/
│   ├── hmi_master.py
│   └── normal_client.py
├── core/
│   ├── modbus.py
│   ├── config.py
│   └── plc_config.yaml
└── tools/
    └── attacks_menu.py
```

---

## 2. Traffic Analysis – quick_modbus_stats

### Purpose

`quick_modbus_stats.py` performs **lightweight, deterministic feature extraction** from `.pcap` / `.pcapng` files.

It is intentionally **non-ML**, used to:

- Validate simulation correctness
- Verify attack visibility
- Provide baseline statistics for unsupervised learning

### Extracted Features

| Feature               | Description                              |
|----------------------|------------------------------------------|
| total_pkts            | Total Modbus packets                     |
| duration_s            | Capture duration                         |
| pkts_per_sec          | Traffic intensity                        |
| fc3_count             | Read Holding Registers                  |
| fc6_count             | Write Single Register                   |
| fc6_distinct_addrs    | Unique registers written                |
| fc6_entropy           | Write distribution entropy              |
| mean_frame_len        | Avg. Modbus frame size                  |
| std_frame_len         | Frame size variance                     |
| num_flows             | TCP flow count                          |
| ports_seen_dst        | Destination port distribution           |

### Usage

```bash
python -m analysis.quick_modbus_stats
python -m analysis.quick_modbus_stats capture/pcap/example.pcapng
```

Requirements:

- tshark
- Decode-as for tcp.port == 502 and 1502

---

## 3. API – Runtime Pipeline (Upcoming)

### Goal

Read-only, low-jitter access to:

- Captured PCAP metadata
- Extracted features
- Scenario state
- Runtime health information

Used only for:

- Node-RED integration
- Monitoring
- Dataset export
- Experiment orchestration

### API Structure

```
api/
├── app.py
├── models.py
├── pcap_export.py
└── runner.py
```

Planned consumers:

- Node-RED
- Telegraf
- InfluxDB
- Grafana

### Design Principles

- No interference with capture
- No additional jitter
- Stateless API
- Offline ML training

---

## 4. Runtime Pipeline Concept

```
[ Simulation ]
      ↓
[ dumpcap ]
      ↓
[ PCAP ]
      ↓
[ Feature Extraction ]
      ↓
[ Unsupervised Model ]
      ↓
[ API / Node-RED / Visualization ]
```

---

## Status Summary

| Component                                  | Status        |
|--------------------------------------------|---------------|
| Simulation                                 | ✅ Stable     |
| Proxy spoofing                             | ✅ Verified   |
| Packet capture                             | ✅ Verified   |
| Feature extraction                         | ✅ Implemented|
| API skeleton                               | ✅ Ready     |
| Node-RED,Telegraf and InfluxDB integration | ⏳ Next step |
| Unsupervised ML model                      | ⏳ Planned   |
