"""op-contract-listDashboards-lifecycle."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-listDashboards-lifecycle"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDashboards filtered by a dashboard's own prefix returns exactly that dashboard (name and ARN),
    an unrelated prefix returns nothing, and after DeleteDashboards the own prefix returns nothing."""
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name("sim2real-cwdashx-").replace("-", "_")
    body = {
        "widgets": [
            {"type": "text", "x": 0, "y": 0, "width": 3, "height": 3, "properties": {"markdown": "hi"}}
        ]
    }
    cw.put_dashboard(DashboardName=name, DashboardBody=json.dumps(body))
    ctx.on_cleanup(lambda: _safe_delete_dashboard(cw, name))


    # success-path contract: found by its own prefix
    entries = cw.list_dashboards(DashboardNamePrefix=name)["DashboardEntries"]
    assert len(entries) == 1, f"expected exactly 1 dashboard for prefix {name!r}, got {entries}"
    assert entries[0]["DashboardName"] == name, (
        f"expected DashboardName {name!r}, got {entries[0]['DashboardName']!r}"
    )
    assert entries[0]["DashboardArn"].endswith(f":dashboard/{name}"), (
        f"expected DashboardArn ending in :dashboard/{name}, got {entries[0]['DashboardArn']!r}"
    )

    # an unrelated prefix must not match this dashboard
    unrelated_prefix = ctx.unique_name("sim2real-cwdashx-nomatch-").replace("-", "_")
    mismatched = cw.list_dashboards(DashboardNamePrefix=unrelated_prefix)["DashboardEntries"]
    assert mismatched == [], f"unrelated prefix unexpectedly matched: {mismatched}"

    # deleting it must remove it from subsequent listings
    cw.delete_dashboards(DashboardNames=[name])
    remaining = _poll_until(
        lambda: cw.list_dashboards(DashboardNamePrefix=name)["DashboardEntries"],
        lambda entries: entries == [],
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert remaining == [], f"deleted dashboard {name!r} still listed: {remaining}"


def _safe_delete_dashboard(cw, name):
    from botocore.exceptions import ClientError

    try:
        cw.delete_dashboards(DashboardNames=[name])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        if predicate(result):
            return result
        time.sleep(interval_s)
        result = probe()
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
