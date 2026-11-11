"""firewall-policy-update-replaces-rule-group-reference."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "firewall-policy-update-replaces-rule-group-reference"
GROUP = "resource-config"
SERVICES = ["network-firewall"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateFirewallPolicy that swaps StatefulRuleGroupReferences actually replaces the
    reference: DescribeFirewallPolicy reflects only the new rule group afterwards, and the
    old rule group's NumberOfAssociations drops to zero so it becomes deletable."""
    nfw = ctx.client("network-firewall")

    def _make_rule_group(sid):
        name = ctx.unique_name(f"sim2real-nfw-rg{sid}-")
        resp = nfw.create_rule_group(
            RuleGroupName=name, Type="STATEFUL", Capacity=10,
            RuleGroup={"RulesSource": {"StatefulRules": [{
                "Action": "ALERT",
                "Header": {"Protocol": "TCP", "Source": "ANY", "SourcePort": "ANY",
                           "Direction": "ANY", "Destination": "ANY", "DestinationPort": "ANY"},
                "RuleOptions": [{"Keyword": f"sid:{sid}"}],
            }]}},
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
        return resp["RuleGroupResponse"]["RuleGroupArn"]

    rg_a_arn = _make_rule_group(1)
    rg_a_cleaned = {"done": False}

    def _cleanup_rg_a():
        if not rg_a_cleaned["done"]:
            try:
                nfw.delete_rule_group(RuleGroupArn=rg_a_arn)
            except ClientError as e:
                if e.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
            rg_a_cleaned["done"] = True

    ctx.on_cleanup(_cleanup_rg_a)
    rg_b_arn = _make_rule_group(2)
    ctx.on_cleanup(lambda: nfw.delete_rule_group(RuleGroupArn=rg_b_arn))

    policy_name = ctx.unique_name("sim2real-nfw-policy-")
    created = nfw.create_firewall_policy(
        FirewallPolicyName=policy_name,
        FirewallPolicy={
            "StatelessDefaultActions": ["aws:forward_to_sfe"],
            "StatelessFragmentDefaultActions": ["aws:forward_to_sfe"],
            "StatefulRuleGroupReferences": [{"ResourceArn": rg_a_arn}],
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    policy_arn = created["FirewallPolicyResponse"]["FirewallPolicyArn"]
    ctx.on_cleanup(lambda: nfw.delete_firewall_policy(FirewallPolicyArn=policy_arn))
    token = created["UpdateToken"]

    before = nfw.describe_firewall_policy(FirewallPolicyArn=policy_arn)
    refs = {r["ResourceArn"] for r in before["FirewallPolicy"]["StatefulRuleGroupReferences"]}
    assert refs == {rg_a_arn}
    rg_a_desc = nfw.describe_rule_group(RuleGroupArn=rg_a_arn)
    assert rg_a_desc["RuleGroupResponse"]["NumberOfAssociations"] == 1

    nfw.update_firewall_policy(
        FirewallPolicyArn=policy_arn, UpdateToken=token,
        FirewallPolicy={
            "StatelessDefaultActions": ["aws:forward_to_sfe"],
            "StatelessFragmentDefaultActions": ["aws:forward_to_sfe"],
            "StatefulRuleGroupReferences": [{"ResourceArn": rg_b_arn}],
        },
    )

    after = nfw.describe_firewall_policy(FirewallPolicyArn=policy_arn)
    refs_after = {r["ResourceArn"] for r in after["FirewallPolicy"]["StatefulRuleGroupReferences"]}
    assert refs_after == {rg_b_arn}, f"expected only rgB referenced, got {refs_after}"

    # NumberOfAssociations is updated asynchronously after the policy update commits;
    # poll to a bounded deadline rather than asserting on the immediate value.
    import time as _time
    deadline = _time.monotonic() + 120
    last_count = None
    while _time.monotonic() < deadline:
        rg_a_desc_after = nfw.describe_rule_group(RuleGroupArn=rg_a_arn)
        last_count = rg_a_desc_after["RuleGroupResponse"]["NumberOfAssociations"]
        if last_count == 0:
            break
        _time.sleep(5)
    assert last_count == 0, f"expected rgA NumberOfAssociations to drop to 0, last observed {last_count}"

    # rgA is no longer referenced by any policy, so it can now be deleted outright
    del_resp = nfw.delete_rule_group(RuleGroupArn=rg_a_arn)
    rg_a_cleaned["done"] = True
    assert del_resp["RuleGroupResponse"]["RuleGroupStatus"] in ("ACTIVE", "DELETING")

    # deletion proven via an independent read, not just the mutating call's own success:
    # RuleGroupStatus goes through DELETING before the rule group disappears entirely.
    delete_deadline = _time.monotonic() + 260
    rg_a_removed = False
    last_rg_status = None
    while _time.monotonic() < delete_deadline:
        try:
            desc = nfw.describe_rule_group(RuleGroupArn=rg_a_arn)
            last_rg_status = desc["RuleGroupResponse"]["RuleGroupStatus"]
            assert last_rg_status in ("ACTIVE", "DELETING"), f"unexpected status while deleting: {last_rg_status}"
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                rg_a_removed = True
                break
            raise
        _time.sleep(2)
    assert rg_a_removed, f"rgA was never removed, last observed status={last_rg_status}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
