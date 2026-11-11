"""rulegroup-custom-label-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "rulegroup-custom-label-round-trip"
GROUP = "representation"
SERVICES = ["wafv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetRuleGroup returns a rule's mixed-case, colon-namespaced RuleLabels exactly after CreateRuleGroup
    and after UpdateRuleGroup adds a second label; once deleted, it fails with
    WAFNonexistentItemException and the exact not-found message.
    """
    wafv2 = ctx.client("wafv2")
    scope = "REGIONAL"
    name = ctx.unique_name("sim2real-behav-rulegroup-lbl-")

    label1 = "shopping:cart:highValue:CustomerVIP"
    rule = _labeled_rule("labelRule", 0, "flagme", [label1], "rglblrulemetric")

    created = wafv2.create_rule_group(
        Name=name,
        Scope=scope,
        Capacity=50,
        VisibilityConfig=_visibility_config("rglblmetric"),
        Rules=[rule],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    rg_id = created["Summary"]["Id"]

    def _cleanup() -> None:
        try:
            current = wafv2.get_rule_group(Name=name, Scope=scope, Id=rg_id)
        except wafv2.exceptions.WAFNonexistentItemException:
            return
        wafv2.delete_rule_group(Name=name, Scope=scope, Id=rg_id, LockToken=current["LockToken"])

    ctx.on_cleanup(_cleanup)

    got = wafv2.get_rule_group(Name=name, Scope=scope, Id=rg_id)
    got_rules = got["RuleGroup"]["Rules"]
    assert len(got_rules) == 1, f"expected 1 rule in RuleGroup {rg_id}, got {len(got_rules)}: {got_rules!r}"
    assert got_rules[0]["RuleLabels"] == [{"Name": label1}], (
        f"expected RuleLabels [{{'Name': {label1!r}}}] after CreateRuleGroup, "
        f"got {got_rules[0].get('RuleLabels')!r}"
    )

    label2 = "shopping:cart:highValue:CustomerVIP:tier2"
    rule2 = _labeled_rule("labelRule", 0, "flagme", [label1, label2], "rglblrulemetric")
    wafv2.update_rule_group(
        Name=name,
        Scope=scope,
        Id=rg_id,
        VisibilityConfig=_visibility_config("rglblmetric"),
        Rules=[rule2],
        LockToken=got["LockToken"],
    )

    got2 = wafv2.get_rule_group(Name=name, Scope=scope, Id=rg_id)
    got_rules2 = got2["RuleGroup"]["Rules"]
    assert len(got_rules2) == 1, (
        f"expected 1 rule in RuleGroup {rg_id} after UpdateRuleGroup, got {len(got_rules2)}: {got_rules2!r}"
    )
    assert got_rules2[0]["RuleLabels"] == [{"Name": label1}, {"Name": label2}], (
        f"expected RuleLabels [{{'Name': {label1!r}}}, {{'Name': {label2!r}}}] after UpdateRuleGroup, "
        f"got {got_rules2[0].get('RuleLabels')!r}"
    )

    delete_token = wafv2.get_rule_group(Name=name, Scope=scope, Id=rg_id)["LockToken"]
    wafv2.delete_rule_group(Name=name, Scope=scope, Id=rg_id, LockToken=delete_token)
    try:
        wafv2.get_rule_group(Name=name, Scope=scope, Id=rg_id)
        raise AssertionError(
            f"expected WAFNonexistentItemException reading RuleGroup {rg_id} after DeleteRuleGroup, "
            "but GetRuleGroup succeeded"
        )
    except wafv2.exceptions.WAFNonexistentItemException as exc:
        assert exc.response["Error"].get("Message") == (
            "AWS WAF couldn\u2019t perform the operation because your resource doesn\u2019t exist."
        ), f"unexpected WAFNonexistentItemException message {exc.response['Error'].get('Message')!r}"


def _visibility_config(metric_name: str) -> dict:
    return {
        "SampledRequestsEnabled": True,
        "CloudWatchMetricsEnabled": True,
        "MetricName": metric_name,
    }


def _labeled_rule(name: str, priority: int, search_string: str, labels: list[str], metric_name: str) -> dict:
    return {
        "Name": name,
        "Priority": priority,
        "Statement": {
            "ByteMatchStatement": {
                "SearchString": search_string.encode("ascii"),
                "FieldToMatch": {"UriPath": {}},
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                "PositionalConstraint": "CONTAINS",
            }
        },
        "Action": {"Count": {}},
        "RuleLabels": [{"Name": label} for label in labels],
        "VisibilityConfig": _visibility_config(metric_name),
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
