"""sampling-rules-priority-ordering-affects-targets."""
from __future__ import annotations

import os
import time

from behavioral_harness import tags

CHECK = "sampling-rules-priority-ordering-affects-targets"
GROUP = "ordering"
SERVICES = ["xray"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Sampling rules with distinct Priority values round-trip their exact Priority through
    GetSamplingRules, and GetSamplingTargets gives each rule its own quota bounded by its own
    ReservoirSize, regardless of statistics submission order or relative Priority.

    Reference: https://docs.aws.amazon.com/xray/latest/api/API_GetSamplingTargets.html
    """
    xray = ctx.client("xray")

    name_low = ctx.unique_name("sim2real-lo-")  # lower Priority number
    name_high = ctx.unique_name("sim2real-hi-")  # higher Priority number

    def _base_rule(name: str, priority: int, reservoir: int) -> dict:
        return {
            "RuleName": name,
            "ResourceARN": "*",
            "Priority": priority,
            "FixedRate": 0.05,
            "ReservoirSize": reservoir,
            "ServiceName": name,
            "ServiceType": "*",
            "Host": "*",
            "HTTPMethod": "*",
            "URLPath": "*",
            "Version": 1,
        }

    xray.create_sampling_rule(SamplingRule=_base_rule(name_low, 137, 3))
    ctx.on_cleanup(lambda: xray.delete_sampling_rule(RuleName=name_low))
    xray.create_sampling_rule(SamplingRule=_base_rule(name_high, 731, 7))
    ctx.on_cleanup(lambda: xray.delete_sampling_rule(RuleName=name_high))

    def _list_order_and_priorities():
        order = []
        priorities = {}
        next_token = None
        for _ in range(50):
            kwargs = {"NextToken": next_token} if next_token else {}
            page = xray.get_sampling_rules(**kwargs)
            for record in page["SamplingRuleRecords"]:
                rule = record["SamplingRule"]
                order.append(rule["RuleName"])
                priorities[rule["RuleName"]] = rule["Priority"]
            next_token = page.get("NextToken")
            if not next_token:
                break
        return order, priorities

    order1, priorities1 = _list_order_and_priorities()
    assert name_low in priorities1 and name_high in priorities1, (
        f"expected both new rules to be listed; got {sorted(priorities1)}"
    )
    # Priority round-trips exactly as set, regardless of list position.
    assert priorities1[name_low] == 137, f"Priority for {name_low!r} corrupted: {priorities1[name_low]}"
    assert priorities1[name_high] == 731, f"Priority for {name_high!r} corrupted: {priorities1[name_high]}"

    # Real AWS lists SamplingRuleRecords by RuleName, not Priority, but no order is documented,
    # so a second call must only list both rules again.
    order2, _ = _list_order_and_priorities()
    assert name_low in order2 and name_high in order2, (
        f"GetSamplingRules dropped a rule on a second call: {order1!r} vs {order2!r}"
    )

    client_id = os.urandom(12).hex()
    now = time.time()
    stats = [
        {
            "RuleName": name_high,  # submitted out of priority order on purpose
            "ClientID": client_id,
            "Timestamp": now,
            "RequestCount": 10,
            "SampledCount": 5,
            "BorrowCount": 0,
        },
        {
            "RuleName": name_low,
            "ClientID": client_id,
            "Timestamp": now,
            "RequestCount": 10,
            "SampledCount": 5,
            "BorrowCount": 0,
        },
    ]
    deadline = time.monotonic() + 90.0
    targets_by_name: dict = {}
    unprocessed = None
    have_quota = False
    while time.monotonic() < deadline:
        call_now = time.time()
        for s in stats:
            s["Timestamp"] = call_now
        targets_resp = xray.get_sampling_targets(SamplingStatisticsDocuments=stats)
        targets_by_name = {
            t["RuleName"]: t for t in targets_resp.get("SamplingTargetDocuments", [])
        }
        unprocessed = targets_resp.get("UnprocessedStatistics")
        have_quota = (
            "ReservoirQuota" in targets_by_name.get(name_low, {})
            and "ReservoirQuota" in targets_by_name.get(name_high, {})
        )
        if have_quota:
            break
        time.sleep(5.0)

    assert not unprocessed, f"unexpected unprocessed statistics: {unprocessed}"
    assert name_low in targets_by_name, f"no target allocated for {name_low}"
    assert name_high in targets_by_name, f"no target allocated for {name_high}"
    # ReservoirQuota is optional: X-Ray may need a few statistics submissions before it
    # allocates one, hence the poll above.
    assert have_quota, (
        f"no ReservoirQuota granted to either rule within {90.0}s: "
        f"{targets_by_name.get(name_low)!r}, {targets_by_name.get(name_high)!r}"
    )
    assert targets_by_name[name_low]["ReservoirQuota"] <= 3, targets_by_name[name_low]
    assert targets_by_name[name_high]["ReservoirQuota"] <= 7, targets_by_name[name_high]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

