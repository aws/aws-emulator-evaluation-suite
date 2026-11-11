"""get-dashboard-and-notfound-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "get-dashboard-and-notfound-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetDashboard returns the exact DashboardBody/DashboardArn that PutDashboard
    stored, and is rejected with ResourceNotFound for a dashboard name that was
    never created."""
    cw = ctx.client("cloudwatch")
    dash_name = ctx.unique_name("sim2real-behav-dash-")
    body = {
        "widgets": [
            {
                "type": "text",
                "x": 0,
                "y": 0,
                "width": 6,
                "height": 2,
                "properties": {"markdown": "sim2real behavioral check"},
            }
        ]
    }
    put_resp = cw.put_dashboard(DashboardName=dash_name, DashboardBody=json.dumps(body))
    assert put_resp["DashboardValidationMessages"] == [], put_resp["DashboardValidationMessages"]
    ctx.on_cleanup(lambda: cw.delete_dashboards(DashboardNames=[dash_name]))

    got = cw.get_dashboard(DashboardName=dash_name)
    assert got["DashboardName"] == dash_name, got["DashboardName"]
    assert json.loads(got["DashboardBody"]) == body, got["DashboardBody"]
    assert got["DashboardArn"].endswith(f"dashboard/{dash_name}"), got["DashboardArn"]

    # Error boundary: a dashboard name that was never created is rejected.
    bogus_name = ctx.unique_name("sim2real-behav-dash-missing-")
    code, message = _error(lambda: cw.get_dashboard(DashboardName=bogus_name))
    assert code == "ResourceNotFound", f"expected ResourceNotFound, got {code!r}"
    assert message == f"Dashboard {bogus_name} does not exist", f"unexpected GetDashboard message {message!r}"


def _error(fn):
    """Call fn(); return its botocore (Error code, Error message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a lookup real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
