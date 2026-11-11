"""get-ops-summary-aggregates-opsitems."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "get-ops-summary-aggregates-opsitems"
GROUP = "state-machine"
SERVICES = ["ssm"]

_NUM_ITEMS = 3


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetOpsSummary's Status count, scoped to freshly created OpsItems, reports them all Open.

    New OpsItems start in status Open, so the Open group count must equal the number created."""
    ssm = ctx.client("ssm")

    ops_item_ids = []
    for i in range(_NUM_ITEMS):
        resp = ssm.create_ops_item(
            Title=ctx.unique_name("sim2real-behav-opsitem-"),
            Source="sim2real-behavioral-check",
            Description=f"behavioral fidelity check ops item {i}",
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
        item_id = resp["OpsItemId"]
        ops_item_ids.append(item_id)
        ctx.on_cleanup(lambda oid=item_id: ssm.delete_ops_item(OpsItemId=oid))

    aggregators = [
        {
            "AggregatorType": "count",
            "TypeName": "AWS:OpsItem",
            "AttributeName": "Status",
            "Filters": [{"Key": "AWS:OpsItem.OpsItemId", "Values": ops_item_ids, "Type": "Equal"}],
        }
    ]

    def _probe():
        resp = ssm.get_ops_summary(Aggregators=aggregators, MaxResults=50)
        return _sum_status_count(resp, "Open")

    open_count = _poll_until(_probe, lambda count: count >= _NUM_ITEMS, timeout_s=60.0, interval_s=3.0)
    assert open_count == _NUM_ITEMS, (
        f"GetOpsSummary reported {open_count} Open OpsItems among the {_NUM_ITEMS} just created"
    )


def _sum_status_count(resp: dict, status: str) -> int:
    total = 0
    for entity in resp.get("Entities", []):
        data = entity.get("Data", {})
        for type_payload in data.values():
            for content in type_payload.get("Content", []):
                if content.get("Status") == status and "Count" in content:
                    total += int(content["Count"])
    return total


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
