"""get-sampling-rules-returns-priority-ordered."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-sampling-rules-returns-priority-ordered"
GROUP = "ordering"
SERVICES = ["xray"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetSamplingRules returns SamplingRuleRecords sorted ascending by Priority, even
    though the rules were created in a different, non-sorted priority order."""
    xray = ctx.client("xray")

    names_by_priority = {
        700: ctx.unique_name("sim2real-p700-"),
        200: ctx.unique_name("sim2real-p200-"),
        450: ctx.unique_name("sim2real-p450-"),
    }
    # Create out of priority order on purpose: 700, then 200, then 450.
    for priority in (700, 200, 450):
        name = names_by_priority[priority]
        xray.create_sampling_rule(
            SamplingRule={
                "RuleName": name,
                "ResourceARN": "*",
                "Priority": priority,
                "FixedRate": 0.05,
                "ReservoirSize": 1,
                "ServiceName": "*",
                "ServiceType": "*",
                "Host": "*",
                "HTTPMethod": "*",
                "URLPath": "*",
                "Version": 1,
            },
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
        ctx.on_cleanup(lambda n=name: xray.delete_sampling_rule(RuleName=n))

    all_records = _list_all_sampling_rules(xray)
    our_names = set(names_by_priority.values())
    ours_in_order = [
        rec["SamplingRule"]["RuleName"]
        for rec in all_records
        if rec["SamplingRule"]["RuleName"] in our_names
    ]
    assert len(ours_in_order) == 3, f"expected 3 of our rules, saw {ours_in_order}"

    expected_order = [names_by_priority[p] for p in sorted(names_by_priority)]
    assert ours_in_order == expected_order, (
        f"GetSamplingRules did not return our rules in ascending-Priority order: "
        f"got {ours_in_order}, expected {expected_order}"
    )


def _list_all_sampling_rules(xray):
    records = []
    next_token = None
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        resp = xray.get_sampling_rules(**kwargs)
        records.extend(resp["SamplingRuleRecords"])
        next_token = resp.get("NextToken")
        if not next_token:
            return records


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
