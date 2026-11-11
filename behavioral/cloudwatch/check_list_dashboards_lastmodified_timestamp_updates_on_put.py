"""list-dashboards-lastmodified-timestamp-updates-on-put."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta

from behavioral_harness import tags

CHECK = "list-dashboards-lastmodified-timestamp-updates-on-put"
GROUP = "telemetry"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDashboards' LastModified field for a dashboard advances after a later PutDashboard
    call updates the same dashboard body, proving change tracking is server-enforced (not a
    static creation-time stamp)."""
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name("sim2real-behav-dash-")
    account = ctx.client("sts").get_caller_identity()["Account"]
    dashboard_arn = f"arn:aws:cloudwatch::{account}:dashboard/{name}"

    body_v1 = json.dumps({"widgets": [{"type": "text", "x": 0, "y": 0, "width": 6, "height": 2,
                                        "properties": {"markdown": "v1"}}]})
    cw.put_dashboard(DashboardName=name, DashboardBody=body_v1)
    ctx.on_cleanup(lambda: cw.delete_dashboards(DashboardNames=[name]))
    cw.tag_resource(ResourceARN=dashboard_arn, Tags=[{"Key": "sim2real-behav", "Value": name}])

    entry0 = _find_dashboard(cw, name)
    assert entry0 is not None, "dashboard missing from ListDashboards immediately after PutDashboard"
    t0 = entry0["LastModified"]
    size0 = entry0["Size"]

    # PutDashboard's LastModified has whole-second resolution; wait for the wall clock to reach
    # the start of the second after t0 so the coming write cannot land in the same bucket.
    _wait_past_second_boundary(t0)

    body_v2 = json.dumps({"widgets": [{"type": "text", "x": 0, "y": 0, "width": 6, "height": 2,
                                        "properties": {"markdown": "v2-updated-body-longer"}}]})
    cw.put_dashboard(DashboardName=name, DashboardBody=body_v2)

    entry1 = _poll_for_lastmodified_advance(cw, name, t0, _budget_s(ctx, 30.0), ctx=ctx)
    assert entry1["LastModified"] > t0, "LastModified did not advance after the second PutDashboard"
    assert entry1["Size"] != size0, "Size did not reflect the updated dashboard body"

    stored_body = json.loads(cw.get_dashboard(DashboardName=name)["DashboardBody"])
    assert stored_body["widgets"][0]["properties"]["markdown"] == "v2-updated-body-longer", (
        f"GetDashboard body did not reflect the update: {stored_body}"
    )


def _find_dashboard(cw, name: str):
    resp = cw.list_dashboards(DashboardNamePrefix=name)
    for entry in resp.get("DashboardEntries", []):
        if entry["DashboardName"] == name:
            return entry
    return None


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_past_second_boundary(baseline_ts, timeout_s: float = 5.0) -> None:
    deadline = time.monotonic() + timeout_s
    next_second = baseline_ts.replace(microsecond=0) + timedelta(seconds=1)
    while True:
        if datetime.now(baseline_ts.tzinfo) >= next_second:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"wall clock never advanced past dashboard LastModified {baseline_ts} within {timeout_s}s"
            )
        time.sleep(0.25)


def _poll_for_lastmodified_advance(cw, name: str, baseline_ts, timeout_s: float = 30.0, ctx=None):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        entry = _find_dashboard(cw, name)
        if entry is not None and entry["LastModified"] > baseline_ts:
            return entry
        time.sleep(1)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"LastModified for dashboard {name} to advance: the run budget ended "
                           f"first; not graded")
    raise AssertionError(f"LastModified for dashboard {name} never advanced past {baseline_ts}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
