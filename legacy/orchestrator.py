import importlib, threading, os

EVENTS_PATH = os.path.join("scenarios", "events.json")

def run_step(step, g):
    kind = step["kind"]
    mod = "generate_normal" if kind=="normal" else f"attacks.{kind}"
    m = importlib.import_module(mod)
    params = step.get("params", {})
    kwargs = dict(plc_host=g["plc_host"], plc_port=g["plc_port"], unit_id=g["unit_id"], **params)
    if kind == "normal":
        # normal leci w tle, aż do końca całego przebiegu
        th = threading.Thread(target=m.run, kwargs=kwargs, daemon=True)
        th.start()
        return th
    else:
        # atak uruchamiany synchronicznie na duration_s
        m.run(**kwargs, duration_s=step["duration_s"])

def main():
    # injector/orchestrator.py
    import os, json, time, threading, importlib, logging
    import yaml

    from injector.core.markers import mark  # package-relative import

    EVENTS_PATH = os.path.join("scenarios", "events.json")

    # --- marker settings ---
    MARKER_ADDR = 10  # %MW10 in OpenPLC
    SESSION_START = 0xACE1  # optional session marker
    SESSION_END = 0xACE2

    # Steps that should run in background (no duration, kept alive)
    BACKGROUND_KINDS = {"normal", "hmi_master"}

    log = logging.getLogger("orchestrator")

    def _qualname(kind: str) -> str:
        """
        Map 'kind' to a fully qualified module name inside the 'injector' package.
        - 'normal'           -> injector.generate_normal
        - 'hmi_master'       -> injector.hmi_master
        - 'scan'             -> injector.attacks.scan
        - 'scan_readonly'    -> injector.attacks.scan_readonly
        - 'write_injection'  -> injector.attacks.write_injection
        - 'network_scan'     -> injector.attacks.network_scan
        """
        if kind in ("normal", "hmi_master"):
            return f"injector.{kind if kind != 'normal' else 'generate_normal'}"
        return f"injector.attacks.{kind}"

    def run_step(step, g):
        """
        Runs a single step.
        Returns a Thread if step is background, else None.
        """
        kind = step["kind"]
        modname = _qualname(kind)
        m = importlib.import_module(modname)

        params = step.get("params", {})
        kwargs = dict(plc_host=g["plc_host"], plc_port=g["plc_port"], unit_id=g["unit_id"], **params)

        if kind in BACKGROUND_KINDS or step.get("duration_s", 0) == 0:
            th = threading.Thread(target=m.run, kwargs=kwargs, daemon=True)
            th.start()
            return th
        else:
            # foreground step (has duration_s)
            m.run(**kwargs, duration_s=step["duration_s"])
            return None

    def main():
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s %(levelname)s %(name)s: %(message)s"
        )

        cfg = yaml.safe_load(open("scenarios/scenario.yaml", "r", encoding="utf-8"))
        g = cfg["global"]
        events = []
        background_threads = []

        # Optional session start marker
        try:
            mark(g["plc_host"], g["plc_port"], g["unit_id"], SESSION_START, addr=MARKER_ADDR)
        except Exception as e:
            log.warning(f"Session start marker failed: {e}")

        t0 = time.time()

        for idx, step in enumerate(cfg["run"]):
            # wait until scheduled start
            start_after = float(step.get("start_after_s", 0))
            while time.time() < t0 + start_after:
                time.sleep(0.05)

            kind = step["kind"]
            name = step.get("name", f"step_{idx}")

            # per-step markers
            start_marker = 0xB000 + idx
            end_marker = 0xD000 + idx

            ev = {"index": idx, "name": name, "label": kind, "start": time.time(), "end": None,
                  "start_marker": start_marker, "end_marker": end_marker, "marker_addr": MARKER_ADDR}

            # Write start marker
            try:
                mark(g["plc_host"], g["plc_port"], g["unit_id"], start_marker, addr=MARKER_ADDR)
            except Exception as e:
                log.warning(f"Start marker failed for {name}: {e}")

            try:
                log.info(f"STEP START [{idx}] {name} ({kind})")
                th = run_step(step, g)
                if th is not None:
                    background_threads.append({"thread": th, "name": name, "kind": kind})
                    log.info(f"Background step '{name}' started (thread daemon)")
                else:
                    log.info(f"Foreground step '{name}' finished")
            finally:
                # For foreground steps we can immediately mark end.
                # For background steps we leave 'end' as None (will end with the session).
                if kind not in BACKGROUND_KINDS and step.get("duration_s", 0) != 0:
                    ev["end"] = time.time()
                    try:
                        mark(g["plc_host"], g["plc_port"], g["unit_id"], end_marker, addr=MARKER_ADDR)
                    except Exception as e:
                        log.warning(f"End marker failed for {name}: {e}")

            events.append(ev)

        # Orchestrator end: background threads are daemons, they will exit with process.
        # Optionally sleep a short moment to let last packets flush
        time.sleep(0.5)

        # Session end marker
        try:
            mark(g["plc_host"], g["plc_port"], g["unit_id"], SESSION_END, addr=MARKER_ADDR)
        except Exception as e:
            log.warning(f"Session end marker failed: {e}")

        # Save ground-truth timeline
        os.makedirs(os.path.dirname(EVENTS_PATH), exist_ok=True)
        with open(EVENTS_PATH, "w", encoding="utf-8") as f:
            json.dump(events, f, indent=2)
        log.info(f"Wrote ground truth to {EVENTS_PATH}")

    if __name__ == "__main__":
        main()
