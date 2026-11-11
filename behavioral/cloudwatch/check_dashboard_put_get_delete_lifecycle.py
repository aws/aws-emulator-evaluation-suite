"""dashboard-put-get-delete-lifecycle."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "dashboard-put-get-delete-lifecycle"
GROUP = "dashboard"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutDashboard stores the exact DashboardBody JSON, GetDashboard round-trips
    it, and after DeleteDashboards the dashboard is genuinely gone (not just
    unlisted)."""
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name("sim2real-behav-dash-")
    body = {
        "widgets": [
            {
                "type": "text",
                "x": 0,
                "y": 0,
                "width": 6,
                "height": 3,
                "properties": {"markdown": "## sim2real behavioral test dashboard"},
            }
        ]
    }

    cw.put_dashboard(DashboardName=name, DashboardBody=json.dumps(body))
    cleaned = {"done": False}

    def _cleanup():
        if not cleaned["done"]:
            cw.delete_dashboards(DashboardNames=[name])

    ctx.on_cleanup(_cleanup)

    fetched = cw.get_dashboard(DashboardName=name)
    assert fetched["DashboardName"] == name, f"expected DashboardName {name!r}, got {fetched['DashboardName']!r}"
    assert json.loads(fetched["DashboardBody"]) == body, fetched["DashboardBody"]

    names = [e["DashboardName"] for e in cw.list_dashboards()["DashboardEntries"]]
    assert name in names, f"expected {name} in ListDashboards, got {names}"

    cw.delete_dashboards(DashboardNames=[name])
    cleaned["done"] = True

    code, message = _refusal(lambda: cw.get_dashboard(DashboardName=name))
    assert code == "ResourceNotFound", f"expected ResourceNotFound after delete, got {code} ({message!r})"
    assert message == f"Dashboard {name} does not exist", f"unexpected ResourceNotFound message {message!r}"


def _refusal(fn):
    """Call fn(); return botocore (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the dashboard to be gone after delete, but the read SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
