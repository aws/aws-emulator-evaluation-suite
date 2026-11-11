"""dashboard-crud-round-trip."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "dashboard-crud-round-trip"
GROUP = "control-plane"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutDashboard/GetDashboard/ListDashboards/DeleteDashboards form a coherent
    lifecycle: the body round-trips semantically and the dashboard disappears from
    both Get and List after deletion."""
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name("sim2real-dash-")
    body = {"widgets": [{"type": "text", "x": 0, "y": 0, "width": 6, "height": 2, "properties": {"markdown": "sim2real"}}]}

    put_resp = cw.put_dashboard(
        DashboardName=name,
        DashboardBody=json.dumps(body),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    errors = [m for m in put_resp.get("DashboardValidationMessages", [])]
    assert not errors, f"unexpected validation messages for a valid dashboard body: {errors}"
    ctx.on_cleanup(lambda: cw.delete_dashboards(DashboardNames=[name]))

    got = cw.get_dashboard(DashboardName=name)
    assert got["DashboardName"] == name, f"expected DashboardName {name!r}, got {got['DashboardName']!r}"
    assert json.loads(got["DashboardBody"]) == body, (
        f"GetDashboard body does not round-trip the PutDashboard body: {got['DashboardBody']}"
    )

    names = {e["DashboardName"] for e in cw.list_dashboards()["DashboardEntries"]}
    assert name in names, "dashboard missing from ListDashboards after creation"

    cw.delete_dashboards(DashboardNames=[name])
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
