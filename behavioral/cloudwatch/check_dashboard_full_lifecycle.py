"""dashboard-full-lifecycle."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "dashboard-full-lifecycle"
GROUP = "state"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutDashboard overwrites the previous body entirely; delete makes it 404."""
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name("sim2real-cw-dash-")

    body1 = {
        "widgets": [
            {"type": "text", "x": 0, "y": 0, "width": 6, "height": 6, "properties": {"markdown": "hello-1"}}
        ]
    }
    cw.put_dashboard(
        DashboardName=name,
        DashboardBody=json.dumps(body1),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )

    def _cleanup():
        try:
            cw.delete_dashboards(DashboardNames=[name])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFound":
                raise

    ctx.on_cleanup(_cleanup)

    got = json.loads(cw.get_dashboard(DashboardName=name)["DashboardBody"])
    assert len(got["widgets"]) == 1, f"expected 1 widget after initial PutDashboard, got {len(got['widgets'])}"
    assert got["widgets"][0]["properties"]["markdown"] == "hello-1", (
        f"expected markdown 'hello-1', got {got['widgets'][0]['properties'].get('markdown')!r}"
    )

    body2 = {
        "widgets": [
            {"type": "text", "x": 0, "y": 0, "width": 6, "height": 6, "properties": {"markdown": "hello-2a"}},
            {"type": "text", "x": 6, "y": 0, "width": 6, "height": 6, "properties": {"markdown": "hello-2b"}},
        ]
    }
    cw.put_dashboard(DashboardName=name, DashboardBody=json.dumps(body2))
    got = json.loads(cw.get_dashboard(DashboardName=name)["DashboardBody"])
    assert len(got["widgets"]) == 2, "PutDashboard must fully overwrite, not merge, the prior body"
    markdowns = {w["properties"]["markdown"] for w in got["widgets"]}
    assert markdowns == {"hello-2a", "hello-2b"}, f"expected {{'hello-2a', 'hello-2b'}}, got {markdowns}"
    assert "hello-1" not in markdowns, f"stale widget from the overwritten body survived: {markdowns}"

    entries = [e["DashboardName"] for e in cw.list_dashboards(DashboardNamePrefix=name)["DashboardEntries"]]
    assert name in entries, f"expected {name} in ListDashboards(prefix={name}), got {entries}"

    cw.delete_dashboards(DashboardNames=[name])
    code, message = _refusal(lambda: cw.get_dashboard(DashboardName=name))
    assert code == "ResourceNotFound", f"unexpected error code after delete: {code} ({message!r})"
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
