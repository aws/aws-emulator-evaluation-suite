"""put-dashboard-round-trip-and-delete."""
from __future__ import annotations

import json
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-dashboard-round-trip-and-delete"
GROUP = 'dashboards'
SERVICES = ['cloudwatch']

def _err(fn):
    """Call fn(); return the botocore Error dict and HTTP status. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}), exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutDashboard/GetDashboard round-trip the body; after DeleteDashboards it is gone."""
    cw = ctx.client("cloudwatch")
    dashboard_name = ctx.unique_name("sim2real-behav-cwprobe-dash-")
    ctx.on_cleanup(lambda _n=dashboard_name: cw.delete_dashboards(DashboardNames=[_n]))
    body = {
        "widgets": [
            {
                "type": "text",
                "x": 0,
                "y": 0,
                "width": 3,
                "height": 3,
                "properties": {"markdown": "hello from behavioral check"},
            }
        ]
    }

    put_resp = cw.put_dashboard(DashboardName=dashboard_name, DashboardBody=json.dumps(body), Tags=[{"Key": "sim2real", "Value": CHECK}])
    assert put_resp.get("DashboardValidationMessages", []) == [], (
        f"expected no validation messages for a well-formed dashboard, "
        f"got {put_resp.get('DashboardValidationMessages')}"
    )

    resp = cw.get_dashboard(DashboardName=dashboard_name)
    assert resp["DashboardName"] == dashboard_name, (
        f"expected GetDashboard to return {dashboard_name}, got {resp['DashboardName']}"
    )
    round_tripped = json.loads(resp["DashboardBody"])
    assert round_tripped["widgets"][0]["properties"]["markdown"] == "hello from behavioral check", (
        f"expected the exact markdown to round-trip, got {round_tripped}"
    )

    cw.delete_dashboards(DashboardNames=[dashboard_name])

    def op():
        return cw.get_dashboard(DashboardName=dashboard_name)

    # Beat 1: the by-name read is ResourceNotFound, 404, and the message names the dashboard.
    error, status = _err(op)
    assert error.get("Code") == "ResourceNotFound", f"expected ResourceNotFound after delete, got {error!r}"
    assert status == 404, f"expected HTTP 404 for GetDashboard after delete, got {status!r}"
    expected_message = f"Dashboard {dashboard_name} does not exist"
    assert error.get("Message") == expected_message, f'expected the message {expected_message!r}, got {error.get("Message")!r}'

    # Beat 2: the dashboard is absent from a listing filtered to its own name.
    listed = [
        d.get("DashboardName")
        for d in cw.list_dashboards(DashboardNamePrefix=dashboard_name).get("DashboardEntries", [])
    ]
    assert dashboard_name not in listed, f"deleted dashboard still listed: {listed!r}"

    # Beat 3: a mutation on the dead dashboard ARN is refused. PutDashboard upserts and
    # DeleteDashboards on a missing name may succeed, so tagging is the dead-id mutation.
    dead_arn = f"arn:aws:cloudwatch::{ctx.account}:dashboard/{dashboard_name}"
    tag_error, tag_status = _err(
        lambda: cw.tag_resource(ResourceARN=dead_arn, Tags=[{"Key": "sim2real", "Value": CHECK}])
    )
    assert tag_error.get("Code") == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException tagging the deleted dashboard, got {tag_error!r}"
    )
    assert tag_status == 404, f"expected HTTP 404 tagging the deleted dashboard, got {tag_status!r}"
    expected_message = ""
    assert tag_error.get("Message") == expected_message, f'expected the message {expected_message!r}, got {tag_error.get("Message")!r}'
    # CloudWatch sends ResourceNotFoundException with an empty message.

    # the name must be reusable after a genuine delete, not left in some
    # tombstoned state that a shallow "unlisted but reserved" emulator would fake
    cw.put_dashboard(DashboardName=dashboard_name, DashboardBody=json.dumps(body), Tags=[{"Key": "sim2real", "Value": CHECK}])
    recreated = cw.get_dashboard(DashboardName=dashboard_name)
    assert recreated["DashboardName"] == dashboard_name, (
        f"expected the deleted dashboard name to be reusable, got {recreated}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
