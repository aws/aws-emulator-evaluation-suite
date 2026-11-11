"""put-dashboard-update-refreshes-lastmodified-in-list."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "put-dashboard-update-refreshes-lastmodified-in-list"
GROUP = "telemetry"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Updating an existing dashboard's body advances its LastModified
    timestamp as reported by ListDashboards -- an observable change signal."""
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name("sim2real-behav-dash-")

    body_v1 = json.dumps(
        {
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
    )
    cw.put_dashboard(DashboardName=name, DashboardBody=body_v1)
    ctx.on_cleanup(lambda: cw.delete_dashboards(DashboardNames=[name]))

    entries = cw.list_dashboards(DashboardNamePrefix=name)["DashboardEntries"]
    assert len(entries) == 1, f"expected exactly one dashboard entry for prefix {name}, got {len(entries)}"
    last_modified_v1 = entries[0]["LastModified"]

    body_v2 = json.dumps(
        {
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
    )

    # A write issued in the same second-resolution bucket as body_v1 can report an
    # unchanged LastModified, so the retry re-applies the update on every attempt
    # (PutDashboard is idempotent) rather than waiting once and hoping the clock moved.
    last_modified_v2 = None
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        cw.put_dashboard(DashboardName=name, DashboardBody=body_v2)
        entries = cw.list_dashboards(DashboardNamePrefix=name)["DashboardEntries"]
        assert len(entries) == 1, (
            f"expected exactly one dashboard entry for prefix {name} after update, got {len(entries)}"
        )
        candidate = entries[0]["LastModified"]
        if candidate > last_modified_v1:
            last_modified_v2 = candidate
            break
        time.sleep(2)

    assert last_modified_v2 is not None, (
        f"ListDashboards LastModified never advanced past {last_modified_v1} "
        f"after PutDashboard update"
    )
    assert last_modified_v2 > last_modified_v1, (
        f"expected LastModified to advance past {last_modified_v1}, got {last_modified_v2}"
    )

    stored_body = json.loads(cw.get_dashboard(DashboardName=name)["DashboardBody"])
    actual_markdown = stored_body["widgets"][0]["properties"]["markdown"]
    assert actual_markdown == "version-2", (
        f"expected GetDashboard body markdown 'version-2' after update, got {actual_markdown!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
