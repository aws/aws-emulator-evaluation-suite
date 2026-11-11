"""dashboard-large-body-persists-without-truncation."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "dashboard-large-body-persists-without-truncation"
GROUP = "representation"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A dashboard body of 480 widgets (over 50 KB) is accepted without validation
    messages and GetDashboard returns it unchanged, every widget including the last intact."""
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name("sim2real-behav-cw-dash-large-")
    widget_count = 480
    filler = "x" * 80
    widgets = [
        {
            "type": "text",
            "x": 0,
            "y": i,
            "width": 3,
            "height": 1,
            "properties": {"markdown": f"widget-{i:04d}-{filler}"},
        }
        for i in range(widget_count)
    ]
    body = {"widgets": widgets}
    body_str = json.dumps(body)
    assert len(body_str) > 50_000, f"body not large enough to be a meaningful test: {len(body_str)}"

    put_resp = cw.put_dashboard(DashboardName=name, DashboardBody=body_str)
    ctx.on_cleanup(lambda: cw.delete_dashboards(DashboardNames=[name]))
    validation_messages = put_resp.get("DashboardValidationMessages", [])
    assert validation_messages == [], (
        f"expected no validation messages for a well-formed large body, got {validation_messages}"
    )

    got = cw.get_dashboard(DashboardName=name)
    parsed = json.loads(got["DashboardBody"])
    assert len(parsed["widgets"]) == widget_count, len(parsed["widgets"])
    assert parsed == body, "dashboard body was modified/truncated on round trip"
    # The last widget is where truncation would manifest first; check it explicitly.
    expected_last = f"widget-{widget_count - 1:04d}-{filler}"
    actual_last = parsed["widgets"][-1]["properties"]["markdown"]
    assert actual_last == expected_last, (
        f"last widget markdown was truncated or altered: expected {expected_last!r}, got {actual_last!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
