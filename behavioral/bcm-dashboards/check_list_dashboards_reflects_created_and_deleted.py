"""list-dashboards-reflects-created-and-deleted."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-dashboards-reflects-created-and-deleted"
GROUP = "state"
SERVICES = ["bcm-dashboards"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDashboards includes a newly-created dashboard's ARN, and stops including it
    after DeleteDashboard (polled, since listing is eventually consistent)."""
    bcm = ctx.client("bcm-dashboards")
    name = ctx.unique_name("sim2real-dash-")
    arn = bcm.create_dashboard(
        name=name,
        widgets=[_cost_widget("W1")],
        resourceTags=[{"key": "env", "value": "sim2real-behavioral"}],
    )["arn"]
    deleted = False

    def _cleanup():
        if not deleted:
            bcm.delete_dashboard(arn=arn)

    ctx.on_cleanup(_cleanup)

    def _listed() -> bool:
        arns: set[str] = set()
        token = None
        while True:
            kwargs = {"nextToken": token} if token else {}
            resp = bcm.list_dashboards(maxResults=100, **kwargs)
            arns.update(d["arn"] for d in resp["dashboards"])
            token = resp.get("nextToken")
            if not token:
                break
        return arn in arns

    assert _poll_until(_listed, timeout_s=30, interval_s=2), "created dashboard never appeared in ListDashboards"

    bcm.delete_dashboard(arn=arn)
    deleted = True

    assert _poll_until(lambda: not _listed(), timeout_s=30, interval_s=2), "deleted dashboard still listed"


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


def _poll_until(predicate, *, timeout_s: float, interval_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval_s)
    return predicate()


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
