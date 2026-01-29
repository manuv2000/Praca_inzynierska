from injector.core.logging_setup import setup_logging
from injector.app.runner import run_scenario
from injector.app.scenario_loader import list_scenarios, build_scenario

import random
import time
from typing import List, Dict, Any, Optional


def _ask_float(prompt: str, default: float) -> float:
    s = input(f"{prompt} [{default}]: ").strip()
    if not s:
        return float(default)
    try:
        return float(s.replace(",", "."))
    except ValueError:
        print("Invalid number, using default.")
        return float(default)


def _ask_int(prompt: str, default: int) -> int:
    s = input(f"{prompt} [{default}]: ").strip()
    if not s:
        return int(default)
    try:
        return int(s)
    except ValueError:
        print("Invalid int, using default.")
        return int(default)


def _ask_yes_no(prompt: str, default: str = "n") -> bool:
    s = input(f"{prompt} (y/n) [{default}]: ").strip().lower()
    if not s:
        s = default
    return s in ("y", "yes", "t", "tak", "1")


def _ask_choice(prompt: str, options: dict, default_key: str):
    s = input(
        f"{prompt} ({', '.join([f'{k}={v}' for k, v in options.items()])}) [{default_key}]: "
    ).strip()
    if not s:
        s = default_key
    return options.get(s, options[default_key])


def _print_scenarios(scenarios: List[Dict[str, Any]]) -> None:
    print("=== PLC Security Simulation ===")
    for i, s in enumerate(scenarios, start=1):
        print(f"{i}) {s.get('id')} — {s.get('label', '')}")


def _pick_scenario_id(scenarios: List[Dict[str, Any]]) -> Optional[str]:
    _print_scenarios(scenarios)
    choice = input("Choose scenario number: ").strip()
    try:
        idx = int(choice) - 1
        return scenarios[idx].get("id")
    except Exception:
        print("Invalid choice")
        return None


def _make_run_label(scenario_id: str, run_idx: int, seed: int) -> str:
    ts = time.strftime("%Y%m%d-%H%M%S")
    return f"{scenario_id}_run{run_idx}_seed{seed}_{ts}"


# -------------------------
# MODE 1: Normal (single scenario, repeats)
# -------------------------
def run_normal_mode(scenario_id: str) -> None:
    # pull defaults for prompts
    _sid, _label, _cfg, _tasks, duration_s, seed, warmup_s, cooldown_s = build_scenario(str(scenario_id))

    print("\n--- NORMAL mode: runtime overrides (ENTER = keep current) ---")
    duration_override = _ask_float("duration_s", float(duration_s or 60.0))
    warmup_override = _ask_float("warmup_s", float(warmup_s or 0.0))
    cooldown_override = _ask_float("cooldown_s", float(cooldown_s or 0.0))

    repeats = _ask_int("repeats", 1)

    seed_mode = _ask_choice(
        "seed mode",
        {"1": "yaml", "2": "random_per_run"},
        default_key="2",
    )

    for i in range(1, repeats + 1):
        # fresh cfg/tasks per run
        scenario_id2, label, cfg, tasks, duration_s2, seed2, warmup_s2, cooldown_s2 = build_scenario(str(scenario_id))

        duration_s2 = duration_override
        warmup_s2 = warmup_override
        cooldown_s2 = cooldown_override

        run_seed = seed2
        if seed_mode == "random_per_run" or run_seed is None:
            run_seed = random.randint(1, 1_000_000)

        run_label = _make_run_label(scenario_id2, i, run_seed)

        # NORMAL mode: keep capture behavior (as before)
        run_scenario(
            scenario_id=scenario_id2,
            label=run_label,
            cfg=cfg,
            tasks=tasks,
            duration_s=duration_s2,
            seed=run_seed,
            warmup_s=warmup_s2,
            cooldown_s=cooldown_s2,
            capture=True,
        )


# -------------------------
# MODE 2: Continuous traffic generator (baseline + short attacks)
# -------------------------
def run_continuous_mode(*, baseline_id: str, attack_ids: List[str]) -> None:
    print("\n--- CONTINUOUS mode (traffic generator, NO capture/files) ---")

    # proportions
    p_attack = _ask_float("attack probability (0..1)", 0.20)
    p_attack = max(0.0, min(1.0, p_attack))

    # durations
    baseline_min = _ask_float("baseline duration min [s]", 30.0)
    baseline_max = _ask_float("baseline duration max [s]", 120.0)
    attack_min = _ask_float("attack duration min [s]", 5.0)
    attack_max = _ask_float("attack duration max [s]", 20.0)

    # seed
    seed_mode = _ask_choice(
        "seed mode",
        {"1": "yaml", "2": "random_per_run"},
        default_key="2",
    )

    # optional: small pause between runs (reduces config-switch jitter spikes)
    pause_s = _ask_float("pause between runs [s]", 0.5)

    print("\n[CONTINUOUS] Running forever. Ctrl+C to stop.\n")
    run_idx = 0
    try:
        while True:
            run_idx += 1

            # choose scenario (baseline vs attack)
            if random.random() < p_attack:
                scenario_id = random.choice(attack_ids)
                duration_s2 = random.uniform(attack_min, attack_max)
            else:
                scenario_id = baseline_id
                duration_s2 = random.uniform(baseline_min, baseline_max)

            # always rebuild fresh cfg/tasks for chosen scenario
            scenario_id2, label, cfg, tasks, duration_s_yaml, seed2, warmup_s2, cooldown_s2 = build_scenario(str(scenario_id))

            # in continuous we force warmup/cooldown to 0 to avoid capture-style behavior,
            # and to reduce "dead time" between short bursts
            warmup_s2 = 0.0
            cooldown_s2 = 0.0

            run_seed = seed2
            if seed_mode == "random_per_run" or run_seed is None:
                run_seed = random.randint(1, 1_000_000)

            run_label = _make_run_label(scenario_id2, run_idx, run_seed)

            # IMPORTANT: continuous mode must not generate files for model
            run_scenario(
                scenario_id=scenario_id2,
                label=run_label,
                cfg=cfg,
                tasks=tasks,
                duration_s=duration_s2,
                seed=run_seed,
                warmup_s=warmup_s2,
                cooldown_s=cooldown_s2,
                capture=False,   # <<< key: do not create pcap/csv/features
            )

            if pause_s and pause_s > 0:
                time.sleep(float(pause_s))

    except KeyboardInterrupt:
        print("\n[CONTINUOUS] Stopped by user.")


def main() -> None:
    setup_logging("INFO")

    scenarios = list_scenarios()
    if not scenarios:
        print("No scenarios found in config/scenarios.yaml")
        return

    mode = _ask_choice(
        "Select mode",
        {"1": "normal (choose scenario + repeats)", "2": "continuous (baseline + short attacks)"},
        default_key="1",
    )

    if mode.startswith("normal"):
        scenario_id = _pick_scenario_id(scenarios)
        if not scenario_id:
            return
        run_normal_mode(scenario_id)
        return

    # continuous mode: ask baseline + attacks list explicitly (separate path)
    print("\nPick BASELINE scenario:")
    baseline_id = _pick_scenario_id(scenarios)
    if not baseline_id:
        return

    # attacks: allow selecting from list by ids or by numbers
    print("\nNow define ATTACK scenarios for continuous mode.")
    print("You can enter scenario numbers separated by commas (e.g. 2,5,7).")
    raw = input("Attack scenario numbers: ").strip()
    if not raw:
        print("No attacks selected -> abort.")
        return

    attack_ids: List[str] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            idx = int(part) - 1
            if 0 <= idx < len(scenarios):
                attack_ids.append(str(scenarios[idx].get("id")))
        except Exception:
            pass

    # dedupe, remove baseline if accidentally added
    attack_ids = [a for a in dict.fromkeys(attack_ids) if a and a != baseline_id]
    if not attack_ids:
        print("Attack list empty (or only baseline) -> abort.")
        return

    run_continuous_mode(baseline_id=baseline_id, attack_ids=attack_ids)


if __name__ == "__main__":
    main()
