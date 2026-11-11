"""rule-group-update-persists-new-rules."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "rule-group-update-persists-new-rules"
GROUP = "resource-config"
SERVICES = ["network-firewall"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateRuleGroup replaces the rule group's RulesSource content, and DescribeRuleGroup
    afterwards reflects exactly the new rules (not a merge with the old ones), with a fresh
    UpdateToken each time."""
    nfw = ctx.client("network-firewall")
    rg_name = ctx.unique_name("sim2real-nfw-rg-")

    def _rule(sid, dest_port):
        return {
            "Action": "ALERT",
            "Header": {"Protocol": "TCP", "Source": "ANY", "SourcePort": "ANY",
                       "Direction": "ANY", "Destination": "ANY", "DestinationPort": dest_port},
            "RuleOptions": [{"Keyword": f"sid:{sid}"}],
        }

    created = nfw.create_rule_group(
        RuleGroupName=rg_name, Type="STATEFUL", Capacity=20,
        RuleGroup={"RulesSource": {"StatefulRules": [_rule(1, "80")]}},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    rule_group_arn = created["RuleGroupResponse"]["RuleGroupArn"]
    ctx.on_cleanup(lambda: nfw.delete_rule_group(RuleGroupArn=rule_group_arn))
    token = created["UpdateToken"]

    updated = nfw.update_rule_group(
        RuleGroupArn=rule_group_arn, UpdateToken=token,
        RuleGroup={"RulesSource": {"StatefulRules": [_rule(2, "443"), _rule(3, "8443")]}},
    )
    assert updated["UpdateToken"] != token, \
        f"expected a fresh UpdateToken after UpdateRuleGroup, got the same token={token}"

    desc = nfw.describe_rule_group(RuleGroupArn=rule_group_arn)
    ports = sorted(r["Header"]["DestinationPort"] for r in desc["RuleGroup"]["RulesSource"]["StatefulRules"])
    assert ports == ["443", "8443"], f"expected the replaced rule set only, got ports={ports}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
