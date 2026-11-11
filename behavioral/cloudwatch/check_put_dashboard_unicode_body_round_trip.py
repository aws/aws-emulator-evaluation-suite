"""put-dashboard-unicode-body-round-trip."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-dashboard-unicode-body-round-trip"
GROUP = "representation"
SERVICES = ["cloudwatch"]


def _err(fn):
    """Call fn(); return the botocore Error dict. A SUCCESS raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetDashboard returns a widget title of CJK, emoji and accented text exactly as PutDashboard stored
    it, and after DeleteDashboards raises ResourceNotFound "Dashboard <name> does not exist"."""
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name("sim2real-behav-cw-dash-unicode-")
    title = "\u65e5\u672c\u8a9e\u30c0\u30f3\u30ac\u30fc\u30ec\u30ba\u5217 \U0001f680\U0001f4ca caf\u00e9 na\u00efve"
    body = {
        "widgets": [
            {
                "type": "text",
                "x": 0,
                "y": 0,
                "width": 6,
                "height": 3,
                "properties": {"markdown": title},
            }
        ]
    }
    put_resp = cw.put_dashboard(DashboardName=name, DashboardBody=json.dumps(body))
    ctx.on_cleanup(lambda: cw.delete_dashboards(DashboardNames=[name]))
    validation_messages = put_resp["DashboardValidationMessages"]
    assert validation_messages == [], f"expected no validation messages, got {validation_messages!r}"

    got = cw.get_dashboard(DashboardName=name)
    parsed = json.loads(got["DashboardBody"])
    actual_title = parsed["widgets"][0]["properties"]["markdown"]
    assert actual_title == title, f"unicode markdown corrupted: expected {title!r}, got {actual_title!r}"
    assert got["DashboardName"] == name, f"expected DashboardName {name!r}, got {got['DashboardName']!r}"

    cw.delete_dashboards(DashboardNames=[name])
    not_found = _err(lambda: cw.get_dashboard(DashboardName=name))
    assert not_found.get("Code") == "ResourceNotFound", (
        f"expected ResourceNotFound after delete, got {not_found!r}"
    )
    assert not_found.get("Message") == f"Dashboard {name} does not exist", (
        f"unexpected not-found message after delete: {not_found.get('Message')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
