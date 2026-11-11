"""rule-group-referenced-by-policy-delete-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rule-group-referenced-by-policy-delete-rejected"
GROUP = "overly-permissive"
SERVICES = ["network-firewall"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteRuleGroup on a stateful rule group that is still referenced by a firewall
    policy is rejected with InvalidOperationException, the rule group is not removed, and
    it becomes deletable once the policy no longer references it (positive control)."""
    nfw = ctx.client("network-firewall")

    rg_name = ctx.unique_name("sim2real-nfw-rg-")
    rg_resp = nfw.create_rule_group(
        RuleGroupName=rg_name, Type="STATEFUL", Capacity=10,
        RuleGroup={"RulesSource": {"StatefulRules": [{
            "Action": "ALERT",
            "Header": {"Protocol": "TCP", "Source": "ANY", "SourcePort": "ANY",
                       "Direction": "ANY", "Destination": "ANY", "DestinationPort": "ANY"},
            "RuleOptions": [{"Keyword": "sid:1"}],
        }]}},
    )
    rule_group_arn = rg_resp["RuleGroupResponse"]["RuleGroupArn"]
    rg_cleaned = {"done": False}

    def _cleanup_rule_group():
        if not rg_cleaned["done"]:
            try:
                nfw.delete_rule_group(RuleGroupArn=rule_group_arn)
            except ClientError as e:
                if e.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
            rg_cleaned["done"] = True

    ctx.on_cleanup(_cleanup_rule_group)

    policy_name = ctx.unique_name("sim2real-nfw-policy-")
    policy_resp = nfw.create_firewall_policy(
        FirewallPolicyName=policy_name,
        FirewallPolicy={
            "StatelessDefaultActions": ["aws:forward_to_sfe"],
            "StatelessFragmentDefaultActions": ["aws:forward_to_sfe"],
            "StatefulRuleGroupReferences": [{"ResourceArn": rule_group_arn}],
        },
    )
    policy_arn = policy_resp["FirewallPolicyResponse"]["FirewallPolicyArn"]
    policy_cleaned = {"done": False}

    def _cleanup_policy():
        if not policy_cleaned["done"]:
            nfw.delete_firewall_policy(FirewallPolicyArn=policy_arn)
            policy_cleaned["done"] = True

    ctx.on_cleanup(_cleanup_policy)

    code, message = _error(lambda: nfw.delete_rule_group(RuleGroupArn=rule_group_arn))
    assert code == "InvalidOperationException", f"expected InvalidOperationException, got {code}"
    expected_message = "Unable to delete the object because it is still in use"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: rule group is still there
    desc = nfw.describe_rule_group(RuleGroupArn=rule_group_arn)
    assert desc["RuleGroupResponse"]["RuleGroupArn"] == rule_group_arn, (
        f"DescribeRuleGroup should still find {rule_group_arn} after the rejected delete, "
        f"got {desc['RuleGroupResponse'].get('RuleGroupArn')!r}"
    )

    # positive control: once the policy no longer references it, delete succeeds
    nfw.delete_firewall_policy(FirewallPolicyArn=policy_arn)
    policy_cleaned["done"] = True

    # NumberOfAssociations drops asynchronously after the referencing policy is deleted;
    # poll to a bounded deadline before retrying the delete.
    import time
    deadline = time.monotonic() + 120
    last_err = None
    while time.monotonic() < deadline:
        try:
            nfw.delete_rule_group(RuleGroupArn=rule_group_arn)
            rg_cleaned["done"] = True
            last_err = None
            break
        except ClientError as e:
            last_err = e.response["Error"]["Code"]
            if last_err != "InvalidOperationException":
                raise
            time.sleep(5)
    assert last_err is None, f"rule group never became deletable, last error={last_err}"

    # terminal read is independent of the delete call: prove the rule group is actually
    # gone, not merely that DeleteRuleGroup returned 200. DeleteRuleGroup is itself
    # asynchronous — real AWS still describes the rule group (status DELETING) for a
    # bounded window before DescribeRuleGroup reports ResourceNotFoundException, so this
    # is a bounded retry, not a single read.
    gone_deadline = time.monotonic() + 300
    gone_code = gone_message = None
    while time.monotonic() < gone_deadline:
        try:
            nfw.describe_rule_group(RuleGroupArn=rule_group_arn)
        except ClientError as e:
            gone_code, gone_message = e.response["Error"]["Code"], e.response["Error"].get("Message")
            if gone_code == "ResourceNotFoundException":
                break
        time.sleep(5)
    assert gone_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from DescribeRuleGroup after the rule group "
        f"became deletable and was deleted, got {gone_code}"
    )
    expected_gone = "No object with the provided name or resource identifier was found"
    assert gone_message == expected_gone, f"expected message {expected_gone!r}, got {gone_message!r}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
