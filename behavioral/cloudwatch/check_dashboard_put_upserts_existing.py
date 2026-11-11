"""dashboard-put-upserts-existing."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "dashboard-put-upserts-existing"
GROUP = "state"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutDashboard is an upsert: calling it twice with the same DashboardName but a
    different DashboardBody overwrites the previous body rather than erroring or
    merging, and GetDashboard reflects only the second body."""
    cw = ctx.client("cloudwatch")
    dashboard_name = ctx.unique_name("sim2real-behav-cw-dashboard-")

    body_v1 = {
        "widgets": [
            {
                "type": "text",
                "x": 0,
                "y": 0,
                "width": 6,
                "height": 2,
                "properties": {"markdown": "version-1"},
            }
        ]
    }
    body_v2 = {
        "widgets": [
            {
                "type": "text",
                "x": 0,
                "y": 0,
                "width": 6,
                "height": 2,
                "properties": {"markdown": "version-2"},
            }
        ]
    }

    cw.put_dashboard(DashboardName=dashboard_name, DashboardBody=json.dumps(body_v1))
    ctx.on_cleanup(lambda: cw.delete_dashboards(DashboardNames=[dashboard_name]))

    fetched_v1 = json.loads(cw.get_dashboard(DashboardName=dashboard_name)["DashboardBody"])
    v1_markdown = fetched_v1["widgets"][0]["properties"]["markdown"]
    assert v1_markdown == "version-1", f"expected initial PutDashboard body, got markdown={v1_markdown!r}"

    cw.put_dashboard(DashboardName=dashboard_name, DashboardBody=json.dumps(body_v2))
    fetched_v2 = json.loads(cw.get_dashboard(DashboardName=dashboard_name)["DashboardBody"])
    v2_markdown = fetched_v2["widgets"][0]["properties"]["markdown"]
    assert v2_markdown == "version-2", (
        f"expected the second PutDashboard to have upserted the body, got markdown={v2_markdown!r}"
    )
    assert len(fetched_v2["widgets"]) == 1, (
        f"upsert should replace, not merge, the widget list, got {len(fetched_v2['widgets'])} widgets"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
