"""put-dashboard-empty-widgets-array-preserved-not-absent."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "put-dashboard-empty-widgets-array-preserved-not-absent"
GROUP = "representation"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A dashboard body with an explicit empty widgets array round-trips as [] rather than being dropped."""
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name("sim2real-cw-empty-widgets-")
    body = {"widgets": []}

    cw.put_dashboard(
        DashboardName=name,
        DashboardBody=json.dumps(body),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: cw.delete_dashboards(DashboardNames=[name]))

    resp = cw.get_dashboard(DashboardName=name)
    round_tripped = json.loads(resp["DashboardBody"])

    assert "widgets" in round_tripped, "widgets key was dropped entirely instead of being an empty array"
    assert round_tripped["widgets"] is not None, "widgets was serialized as null instead of an empty array"
    assert round_tripped["widgets"] == [], f"expected an empty widgets array, got {round_tripped['widgets']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
