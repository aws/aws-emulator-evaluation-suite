"""create-get-dashboard-roundtrip."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "create-get-dashboard-roundtrip"
GROUP = "crud"
SERVICES = ["bcm-dashboards"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDashboard persists name/description/widgets; GetDashboard reflects them,
    a widget id is server-generated (32 hex chars), and un-set width/height are simply
    left unset (the service does not backfill them with defaults in the response)."""
    bcm = ctx.client("bcm-dashboards")
    name = ctx.unique_name("sim2real-dash-")
    widget = _cost_widget("Primary Widget")
    # deliberately omit width/height to exercise the un-set behavior
    assert "width" not in widget and "height" not in widget, widget

    resp = bcm.create_dashboard(
        name=name,
        description="Behavioral fidelity check dashboard.",
        widgets=[widget],
        resourceTags=[{"key": "sim2real", "value": "behavioral"}],
    )
    arn = resp["arn"]
    ctx.on_cleanup(lambda: bcm.delete_dashboard(arn=arn))

    got = bcm.get_dashboard(arn=arn)
    assert got["arn"] == arn, got
    assert got["name"] == name, got["name"]
    assert got["description"] == "Behavioral fidelity check dashboard.", got["description"]
    assert got["type"] == "CUSTOM", got["type"]
    assert len(got["widgets"]) == 1, got["widgets"]
    returned_widget = got["widgets"][0]
    assert returned_widget["title"] == "Primary Widget", returned_widget.get("title")
    assert re.fullmatch(r"[0-9a-f]{32}", returned_widget["id"]), returned_widget.get("id")
    # un-set width/height are not backfilled with a default value in the response;
    # if present at all, they must still respect the documented valid ranges
    if "width" in returned_widget:
        assert 2 <= returned_widget["width"] <= 6, returned_widget["width"]
    if "height" in returned_widget:
        assert 4 <= returned_widget["height"] <= 10, returned_widget["height"]
    assert "createdAt" in got and "updatedAt" in got, got


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
