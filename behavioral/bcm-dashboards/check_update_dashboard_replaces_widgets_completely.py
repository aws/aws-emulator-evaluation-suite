"""update-dashboard-replaces-widgets-completely."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-dashboard-replaces-widgets-completely"
GROUP = "state"
SERVICES = ["bcm-dashboards"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateDashboard's widgets field REPLACES the entire widget set: after updating
    with a single new widget, the previously-existing widgets are gone, not merged."""
    bcm = ctx.client("bcm-dashboards")
    name = ctx.unique_name("sim2real-dash-")
    arn = bcm.create_dashboard(
        name=name,
        widgets=[_cost_widget("Widget A"), _cost_widget("Widget B")],
        resourceTags=[{"key": "env", "value": "sim2real-behavioral"}],
    )["arn"]
    ctx.on_cleanup(lambda: bcm.delete_dashboard(arn=arn))

    before = bcm.get_dashboard(arn=arn)
    before_titles = {w["title"] for w in before["widgets"]}
    assert before_titles == {"Widget A", "Widget B"}, before_titles
    assert len(before["widgets"]) == 2, before["widgets"]

    bcm.update_dashboard(arn=arn, name=name, widgets=[_cost_widget("Widget C")])

    after = bcm.get_dashboard(arn=arn)
    titles = {w["title"] for w in after["widgets"]}
    assert titles == {"Widget C"}, titles
    assert len(after["widgets"]) == 1, after["widgets"]


def _cost_widget(title: str) -> dict:
    return {
        "title": title,
        "configs": [
            {
                "queryParameters": {
                    "costAndUsage": {
                        "metrics": ["UnblendedCost"],
                        "timeRange": {
                            "startTime": {"type": "RELATIVE", "value": "-P1M"},
                            "endTime": {"type": "RELATIVE", "value": "-P0D"},
                        },
                        "granularity": "MONTHLY",
                    }
                },
                "displayConfig": {"table": {}},
            }
        ],
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
