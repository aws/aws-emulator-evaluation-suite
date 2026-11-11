"""app-monitor-empty-vs-absent-domain-list-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "app-monitor-empty-vs-absent-domain-list-preserved"
GROUP = "representation"
SERVICES = ["rum"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An explicitly empty FavoritePages list (it allows zero items, unlike DomainList) on
    CreateAppMonitor reads back from GetAppMonitor as [], not as absent or null.
    """
    rum = ctx.client("rum")
    name = ctx.unique_name("sim2real-rum-")
    rum.create_app_monitor(
        Name=name,
        DomainList=["example.com"],
        AppMonitorConfiguration={"FavoritePages": []},
        Tags={"Team": "rum-fidelity"},
    )
    ctx.on_cleanup(lambda: rum.delete_app_monitor(Name=name))

    monitor = rum.get_app_monitor(Name=name)["AppMonitor"]
    config = monitor.get("AppMonitorConfiguration", {})
    assert "FavoritePages" in config, (
        "explicitly empty FavoritePages list was dropped/coerced to absent on GetAppMonitor"
    )
    assert config["FavoritePages"] == [], (
        f"expected empty list to round-trip as [], got {config['FavoritePages']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
