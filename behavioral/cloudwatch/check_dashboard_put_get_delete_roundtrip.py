"""dashboard-put-get-delete-roundtrip."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "dashboard-put-get-delete-roundtrip"
GROUP = "data-plane"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutDashboard persists the exact widget body; GetDashboard returns it verbatim; DeleteDashboards
    removes it from both an independent Get and an independent List, and the freed name accepts a
    genuinely new body afterward rather than resurrecting the old one."""
    cw = ctx.client("cloudwatch")
    dashboard_name = ctx.unique_name("sim2real-dash-")
    marker = ctx.unique_name("marker-")
    body = {
        "widgets": [
            {
                "type": "text",
                "x": 0,
                "y": 0,
                "width": 6,
                "height": 6,
                "properties": {"markdown": f"# {marker}"},
            }
        ]
    }

    put_resp = cw.put_dashboard(DashboardName=dashboard_name, DashboardBody=json.dumps(body))
    assert put_resp["DashboardValidationMessages"] == [], (
        f"expected no validation messages for a well-formed body, "
        f"got {put_resp['DashboardValidationMessages']}"
    )
    ctx.on_cleanup(lambda: cw.delete_dashboards(DashboardNames=[dashboard_name]))

    get_resp = cw.get_dashboard(DashboardName=dashboard_name)
    assert get_resp["DashboardName"] == dashboard_name, (
        f"expected DashboardName={dashboard_name!r}, got {get_resp['DashboardName']!r}"
    )
    stored_body = json.loads(get_resp["DashboardBody"])
    assert stored_body["widgets"][0]["properties"]["markdown"] == f"# {marker}", (
        f"expected markdown '# {marker}', got "
        f"{stored_body['widgets'][0]['properties'].get('markdown')!r}"
    )
    assert stored_body["widgets"][0]["type"] == "text", (
        f"expected widget type 'text', got {stored_body['widgets'][0].get('type')!r}"
    )

    cw.delete_dashboards(DashboardNames=[dashboard_name])

    code, message = _refusal(lambda: cw.get_dashboard(DashboardName=dashboard_name))
    assert code == "ResourceNotFound", f"expected ResourceNotFound after delete, got {code!r} ({message!r})"
    assert message == f"Dashboard {dashboard_name} does not exist", f"unexpected ResourceNotFound message {message!r}"

    listed = {e["DashboardName"] for e in cw.list_dashboards()["DashboardEntries"]}
    assert dashboard_name not in listed, (
        f"deleted dashboard {dashboard_name} still appears in ListDashboards: {listed}"
    )

    marker2 = ctx.unique_name("marker2-")
    body2 = {
        "widgets": [
            {
                "type": "text",
                "x": 0,
                "y": 0,
                "width": 6,
                "height": 6,
                "properties": {"markdown": f"# {marker2}"},
            }
        ]
    }
    cw.put_dashboard(DashboardName=dashboard_name, DashboardBody=json.dumps(body2))
    reused_body = json.loads(cw.get_dashboard(DashboardName=dashboard_name)["DashboardBody"])
    assert reused_body["widgets"][0]["properties"]["markdown"] == f"# {marker2}", (
        f"expected the freed name to accept a genuinely new body '# {marker2}', got "
        f"{reused_body['widgets'][0]['properties'].get('markdown')!r}"
    )


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
