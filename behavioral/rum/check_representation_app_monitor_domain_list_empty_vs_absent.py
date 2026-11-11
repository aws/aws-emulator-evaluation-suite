"""representation-app-monitor-domain-list-empty-vs-absent."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "representation-app-monitor-domain-list-empty-vs-absent"
GROUP = "representation"
SERVICES = ["rum"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetAppMonitor returns an explicitly empty AppMonitorConfiguration.ExcludedPages as [] and omits
    the key when it was never supplied, so empty and absent stay distinct on read-back."""
    rum = ctx.client("rum")

    name_empty = ctx.unique_name("sim2real-rum-emptycfg-")
    name_absent = ctx.unique_name("sim2real-rum-absentcfg-")

    rum.create_app_monitor(
        Name=name_empty,
        Domain="localhost",
        AppMonitorConfiguration={"ExcludedPages": []},
        Tags={"Team": "rum-fidelity"},
    )
    ctx.on_cleanup(lambda: rum.delete_app_monitor(Name=name_empty))

    rum.create_app_monitor(
        Name=name_absent,
        Domain="localhost",
        AppMonitorConfiguration={"AllowCookies": True},
        Tags={"Team": "rum-fidelity"},
    )
    ctx.on_cleanup(lambda: rum.delete_app_monitor(Name=name_absent))

    empty_cfg = rum.get_app_monitor(Name=name_empty)["AppMonitor"]["AppMonitorConfiguration"]
    absent_cfg = rum.get_app_monitor(Name=name_absent)["AppMonitor"]["AppMonitorConfiguration"]

    assert "ExcludedPages" in empty_cfg, (
        f"explicitly empty ExcludedPages list was dropped/coerced to absent on GetAppMonitor, got {empty_cfg!r}"
    )
    assert empty_cfg["ExcludedPages"] == [], (
        f"expected empty list to round-trip as [], got {empty_cfg['ExcludedPages']!r}"
    )
    assert "ExcludedPages" not in absent_cfg, (
        f"ExcludedPages was never supplied but appeared on read-back as {absent_cfg.get('ExcludedPages')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
