from injector.core.logging_setup import setup_logging
from injector.app.scenario_loader import build_scenario
from injector.app.runner import run_scenario

def main():
    setup_logging("INFO")

    plan = [
        ("baseline", 5),
        ("baseline_write_inj", 5),
        ("baseline_proxy_spoof", 5),
        ("mass_overwrite_only", 5),
    ]

    for scenario_id, repeats in plan:
        for i in range(repeats):
            label, cfg, tasks, duration_s, seed = build_scenario(scenario_id)
            run_scenario(
                label=f"{scenario_id}_run{i+1}",
                cfg=cfg,
                tasks=tasks,
                duration_s=duration_s,
                seed=seed,
            )

if __name__ == "__main__":
    main()
