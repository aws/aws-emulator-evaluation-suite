"""put-dashboard-unicode-widget-body-round-trip."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "put-dashboard-unicode-widget-body-round-trip"
GROUP = "representation"
SERVICES = ["cloudwatch"]

_MARKDOWN = "# 日本語ダッシュボード 🚀 – café résumé"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A dashboard widget body with unicode text round-trips unchanged through PutDashboard/GetDashboard."""
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name("sim2real-cw-uni-dash-")
    body = {
        "widgets": [
            {
                "type": "text",
                "x": 0,
                "y": 0,
                "width": 6,
                "height": 6,
                "properties": {"markdown": _MARKDOWN},
            }
        ]
    }

    cw.put_dashboard(DashboardName=name, DashboardBody=json.dumps(body, ensure_ascii=False))
    ctx.on_cleanup(lambda: cw.delete_dashboards(DashboardNames=[name]))

    resp = cw.get_dashboard(DashboardName=name)
    round_tripped = json.loads(resp["DashboardBody"])
    got_markdown = round_tripped["widgets"][0]["properties"]["markdown"]
    assert got_markdown == _MARKDOWN, (
        f"unicode widget markdown corrupted: expected {_MARKDOWN!r}, got {got_markdown!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
