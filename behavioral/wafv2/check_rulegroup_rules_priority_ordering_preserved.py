"""rulegroup-rules-priority-ordering-preserved."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rulegroup-rules-priority-ordering-preserved"
GROUP = "ordering"
SERVICES = ["wafv2"]

_TAGS_KV = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-rg-order"},
]


def _rule(name: str, priority: int) -> dict:
    return {
        "Name": name,
        "Priority": priority,
        "Statement": {"GeoMatchStatement": {"CountryCodes": ["US"]}},
        "Action": {"Count": {}},
        "VisibilityConfig": {
            "SampledRequestsEnabled": False,
            "CloudWatchMetricsEnabled": False,
            "MetricName": name,
        },
    }


_NOT_FOUND_MESSAGE = "AWS WAF couldn\u2019t perform the operation because your resource doesn\u2019t exist."

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetRuleGroup returns Rules sorted by ascending Priority after both CreateRuleGroup and
    UpdateRuleGroup submit them out of order, with each Priority value preserved exactly;
    after deletion a further mutation fails with the not-found error."""
    wafv2 = ctx.client("wafv2")
    name = ctx.unique_name("sim2real-rg-order-")
    scope = "REGIONAL"
    vis = {"SampledRequestsEnabled": False, "CloudWatchMetricsEnabled": False, "MetricName": name}

    # Submitted in an order that does NOT match ascending Priority.
    initial_rules = [_rule("r-low", 30), _rule("r-mid", 10), _rule("r-high", 20)]

    created = wafv2.create_rule_group(
        Name=name,
        Scope=scope,
        Capacity=30,
        Rules=initial_rules,
        VisibilityConfig=vis,
        Tags=_TAGS_KV,
    )
    summary = created["Summary"]
    rg_id = summary["Id"]

    def _cleanup():
        try:
            cur = wafv2.get_rule_group(Name=name, Scope=scope, Id=rg_id)
            wafv2.delete_rule_group(Name=name, Scope=scope, Id=rg_id, LockToken=cur["LockToken"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
                raise

    ctx.on_cleanup(_cleanup)

    got = wafv2.get_rule_group(Name=name, Scope=scope, Id=rg_id)
    returned_rules = got["RuleGroup"]["Rules"]
    # Priority-ascending order: r-mid(10), r-high(20), r-low(30) -- NOT the
    # r-low, r-mid, r-high request order.
    assert [r["Name"] for r in returned_rules] == ["r-mid", "r-high", "r-low"], (
        f"expected Rules normalized to ascending-Priority order, got "
        f"{[r['Name'] for r in returned_rules]}"
    )
    got_priorities = {r["Name"]: r["Priority"] for r in returned_rules}
    assert got_priorities == {"r-low": 30, "r-mid": 10, "r-high": 20}, (
        f"expected each rule's own Priority preserved exactly, got {got_priorities}"
    )

    # Different insertion order and priorities on update.
    updated_rules = [_rule("r-high", 20), _rule("r-mid", 5), _rule("r-low", 30)]
    wafv2.update_rule_group(
        Name=name,
        Scope=scope,
        Id=rg_id,
        Rules=updated_rules,
        VisibilityConfig=vis,
        LockToken=got["LockToken"],
    )

    got2 = wafv2.get_rule_group(Name=name, Scope=scope, Id=rg_id)
    returned_rules2 = got2["RuleGroup"]["Rules"]
    # New priorities: r-mid=5, r-high=20, r-low=30 -> ascending order is
    # r-mid, r-high, r-low.
    assert [r["Name"] for r in returned_rules2] == ["r-mid", "r-high", "r-low"], (
        f"expected Rules re-normalized to the new ascending-Priority order, got "
        f"{[r['Name'] for r in returned_rules2]}"
    )
    got_priorities2 = {r["Name"]: r["Priority"] for r in returned_rules2}
    assert got_priorities2 == {"r-high": 20, "r-mid": 5, "r-low": 30}, (
        f"expected each rule's own updated Priority preserved exactly, got {got_priorities2}"
    )

    # The delete this check's cleanup would otherwise perform silently: prove the
    # RuleGroup is actually gone and that a further mutation on the dead id fails
    # with the specific not-found error, rather than leaving the delete unasserted.
    wafv2.delete_rule_group(Name=name, Scope=scope, Id=rg_id, LockToken=got2["LockToken"])
    try:
        wafv2.get_rule_group(Name=name, Scope=scope, Id=rg_id)
        raise AssertionError("expected GetRuleGroup on a deleted RuleGroup to fail")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        assert code == "WAFNonexistentItemException", (
            f"expected WAFNonexistentItemException after delete, got {code}"
        )
        message = exc.response.get("Error", {}).get("Message")
        assert message == _NOT_FOUND_MESSAGE, message


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
