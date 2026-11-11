"""update-rule-group-exceeds-capacity-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-rule-group-exceeds-capacity-rejected"
GROUP = "overly-permissive"
SERVICES = ["network-firewall"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateRuleGroup beyond the creation Capacity fails with InvalidRequestException and the exact
    message and keeps the stored rule; an in-capacity update persists Action=DROP; DeleteRuleGroup
    reports DELETING and DescribeRuleGroup then answers ResourceNotFoundException."""
    nfw = ctx.client("network-firewall")
    rg_name = ctx.unique_name("sim2real-nfw-rg-")

    def _rule(sid, action="ALERT"):
        return {
            "Action": action,
            "Header": {"Protocol": "TCP", "Source": "ANY", "SourcePort": "ANY",
                       "Direction": "ANY", "Destination": "ANY", "DestinationPort": "ANY"},
            "RuleOptions": [{"Keyword": f"sid:{sid}"}],
        }

    created = nfw.create_rule_group(
        RuleGroupName=rg_name, Type="STATEFUL", Capacity=10,
        RuleGroup={"RulesSource": {"StatefulRules": [_rule(1)]}},
        Tags=[{"Key": "sim2real:check", "Value": CHECK}],
    )
    rule_group_arn = created["RuleGroupResponse"]["RuleGroupArn"]

    def _cleanup():
        try:
            nfw.delete_rule_group(RuleGroupArn=rule_group_arn)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    token = created["UpdateToken"]
    original_consumed = created["RuleGroupResponse"]["ConsumedCapacity"]

    # Far more rules than the fixed Capacity=10 allows.
    too_many_rules = [_rule(sid) for sid in range(1, 200)]
    code, message = _error(lambda: nfw.update_rule_group(
        RuleGroupArn=rule_group_arn, UpdateToken=token,
        RuleGroup={"RulesSource": {"StatefulRules": too_many_rules}},
    ))
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    expected_message = (
        f"StatefulRules capacity exceeded, parameter: [{len(too_many_rules)}], "
        "context: RulesSource.StatefulRules"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: still the single original rule / same consumed capacity
    desc = nfw.describe_rule_group(RuleGroupArn=rule_group_arn)
    consumed = desc["RuleGroupResponse"]["ConsumedCapacity"]
    assert consumed == original_consumed, \
        f"expected ConsumedCapacity unchanged at {original_consumed}, got {consumed}"
    surviving_rules = desc["RuleGroup"]["RulesSource"]["StatefulRules"]
    assert len(surviving_rules) == 1, \
        f"expected the original single rule to survive the rejected update, got {len(surviving_rules)} rules"
    fresh_token = desc["UpdateToken"]

    # positive control: an update within capacity (same rule, different action) succeeds
    nfw.update_rule_group(
        RuleGroupArn=rule_group_arn, UpdateToken=fresh_token,
        RuleGroup={"RulesSource": {"StatefulRules": [_rule(1, action="DROP")]}},
    )
    updated = nfw.describe_rule_group(RuleGroupArn=rule_group_arn)
    action = updated["RuleGroup"]["RulesSource"]["StatefulRules"][0]["Action"]
    assert action == "DROP", f"expected the in-capacity update to persist Action=DROP, got {action}"

    # deletes prove gone and unusable: DeleteRuleGroup is asynchronous (RuleGroupStatus
    # transitions to DELETING before the resource actually disappears), so bound the wait
    # instead of assuming an immediate not-found.
    deleted = nfw.delete_rule_group(RuleGroupArn=rule_group_arn)
    assert deleted["RuleGroupResponse"]["RuleGroupStatus"] == "DELETING", \
        f"expected DeleteRuleGroup to report DELETING, got {deleted['RuleGroupResponse']['RuleGroupStatus']!r}"
    gone_code, gone_message = _poll_until_not_found(lambda: nfw.describe_rule_group(RuleGroupArn=rule_group_arn))
    assert gone_code == "ResourceNotFoundException", f"expected ResourceNotFoundException after delete, got {gone_code}"
    expected_gone = "No object with the provided name or resource identifier was found"
    assert gone_message == expected_gone, f"expected message {expected_gone!r}, got {gone_message!r}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until_not_found(fn, *, timeout_s=240, interval_s=5):
    """Poll fn() (a describe call) until it raises ClientError; return that error's (code, message).
    Bounded and raises on timeout -- DeleteRuleGroup leaves RuleGroupStatus=DELETING for a
    stretch during which describe still succeeds, so a single immediate read cannot observe
    the terminal not-found state."""
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        try:
            resp = fn()
            last_status = resp["RuleGroupResponse"]["RuleGroupStatus"]
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
        time.sleep(interval_s)
    raise AssertionError(f"rule group not deleted within {timeout_s}s; last status={last_status!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
