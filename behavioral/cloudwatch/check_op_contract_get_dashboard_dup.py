"""op-contract-getDashboard-dup."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "op-contract-getDashboard-dup"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetDashboard returns the name, body and ARN PutDashboard stored, and raises ResourceNotFound
    "Dashboard <name> does not exist" both for a never-created name and for the dashboard once deleted."""
    cw = ctx.client("cloudwatch")
    dash_name = ctx.unique_name("sim2real-behav-cw-dash-")
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
    assert put_resp["DashboardValidationMessages"] == []
    ctx.on_cleanup(lambda: cw.delete_dashboards(DashboardNames=[dash_name]))

    # success-path contract: Get returns exactly the stored body, ARN, and name.
    got = cw.get_dashboard(DashboardName=dash_name)
    assert got["DashboardName"] == dash_name
    assert json.loads(got["DashboardBody"]) == body
    assert got["DashboardArn"].endswith(f"dashboard/{dash_name}")

    # error boundary: a dashboard name that was never created is rejected.
    bogus_name = ctx.unique_name("sim2real-behav-cw-dash-missing-")
    code, message = _error(lambda: cw.get_dashboard(DashboardName=bogus_name))
    assert code == "ResourceNotFound", f"expected ResourceNotFound, got {code!r}"
    expected = f"Dashboard {bogus_name} does not exist"
    assert message == expected, f"expected the exact message {expected!r}, got {message!r}"

    # delete proves gone: once the real dashboard is actually removed, GetDashboard
    # 404s the same specific way -- not just for a name that never existed.
    cw.delete_dashboards(DashboardNames=[dash_name])
    code2, message2 = _error(lambda: cw.get_dashboard(DashboardName=dash_name))
    assert code2 == "ResourceNotFound", f"expected the deleted dashboard to 404, got {code2!r}"
    expected2 = f"Dashboard {dash_name} does not exist"
    assert message2 == expected2, f"expected the exact message {expected2!r}, got {message2!r}"


def _error(fn):
    """Return (code, message) of the ClientError fn raises. A SUCCESS is an AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
