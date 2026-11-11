"""update-dashboard-updated-at-changes."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-dashboard-updated-at-changes"
GROUP = "state"
SERVICES = ["bcm-dashboards"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateDashboard refreshes updatedAt while leaving createdAt untouched."""
    bcm = ctx.client("bcm-dashboards")
    name = ctx.unique_name("sim2real-dash-")
    arn = bcm.create_dashboard(
        name=name,
        widgets=[_cost_widget("W1")],
        resourceTags=[{"key": "env", "value": "sim2real-behavioral"}],
    )["arn"]
    ctx.on_cleanup(lambda: bcm.delete_dashboard(arn=arn))

    before = bcm.get_dashboard(arn=arn)
    created_before = before["createdAt"]
    updated_before = before["updatedAt"]

    def _updated_since_last_call() -> bool:
        # UpdateDashboard is idempotent here (same Description each call), so retrying
        # it is safe; poll for the timestamp to actually advance past updated_before
        # rather than sleeping a fixed duration and hoping resolution was crossed.
        bcm.update_dashboard(arn=arn, name=name, description="now with a description")
        return bcm.get_dashboard(arn=arn)["updatedAt"] > updated_before

    assert _poll_until(_updated_since_last_call, timeout_s=30, interval_s=1), (
        "UpdatedAt never advanced past its pre-update value"
    )

    after = bcm.get_dashboard(arn=arn)
    assert after["createdAt"] == created_before, (
        f"createdAt should be immutable across UpdateDashboard: "
        f"before={created_before!r} after={after['createdAt']!r}"
    )
    assert after["updatedAt"] > updated_before, (
        f"updatedAt should have advanced past its pre-update value: "
        f"before={updated_before!r} after={after['updatedAt']!r}"
    )
    assert after["description"] == "now with a description", (
        f"description should reflect the last UpdateDashboard call: got {after['description']!r}"
    )


def _poll_until(predicate, *, timeout_s: float, interval_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval_s)
    return predicate()


def _cost_widget(title: str) -> dict:
    return {
        "title": title,
        "configs": [
            {
                "queryParameters": {
                    "costAndUsage": {
                        "metrics": ["UnblendedCost"],
                        "timeRange": {
                            "startTime": {"type": "RELATIVE", "value": "-P1M"},
                            "endTime": {"type": "RELATIVE", "value": "-P0D"},
                        },
                        "granularity": "MONTHLY",
                    }
                },
                "displayConfig": {"table": {}},
            }
        ],
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
