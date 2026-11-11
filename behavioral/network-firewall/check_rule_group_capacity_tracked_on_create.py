"""rule-group-capacity-tracked-on-create."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rule-group-capacity-tracked-on-create"
GROUP = "resource-config"
SERVICES = ["network-firewall"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateRuleGroup rejects a Capacity below the rule count with the exact message; a DryRun reports
    the capacity of the 2 rules and persists nothing; the real rule group keeps Capacity and
    ConsumedCapacity equal to that estimate."""
    nfw = ctx.client("network-firewall")

    rules = {"RulesSource": {"StatefulRules": [
        {
            "Action": "DROP",
            "Header": {"Protocol": "TCP", "Source": "ANY", "SourcePort": "ANY",
                       "Direction": "FORWARD", "Destination": "192.0.2.0/24", "DestinationPort": "445"},
            "RuleOptions": [{"Keyword": "sid:1"}],
        },
        {
            "Action": "ALERT",
            "Header": {"Protocol": "UDP", "Source": "ANY", "SourcePort": "ANY",
                       "Direction": "ANY", "Destination": "198.51.100.0/24", "DestinationPort": "53"},
            "RuleOptions": [{"Keyword": "sid:2"}],
        },
    ]}}
    # Per AWS docs, for a stateful rule group the minimum required capacity is the
    # number of individual rules in the group -- here, 2.
    expected_capacity = 2

    # A Capacity below the number of rules is rejected outright (dry run included).
    under_name = ctx.unique_name("sim2real-nfw-rg-under-")
    code, message = _error_code(lambda: nfw.create_rule_group(
        RuleGroupName=under_name, Type="STATEFUL", Capacity=1, RuleGroup=rules, DryRun=True,
    ))
    assert code == "InvalidRequestException", f"expected a capacity-rejection error, got {code}"
    assert message == (
        "StatefulRules capacity exceeded, parameter: [2], context: RulesSource.StatefulRules"
    ), f"unexpected capacity-rejection message: {message!r}"

    # DryRun with sufficient capacity succeeds and makes no changes (not creatable/describable after).
    dry_name = ctx.unique_name("sim2real-nfw-rg-dryrun-")
    dry_resp = nfw.create_rule_group(
        RuleGroupName=dry_name, Type="STATEFUL", Capacity=expected_capacity, RuleGroup=rules, DryRun=True,
    )
    assert dry_resp["RuleGroupResponse"]["Capacity"] == expected_capacity, \
        f"expected DryRun to echo requested Capacity {expected_capacity}, got {dry_resp['RuleGroupResponse']['Capacity']}"
    absent_code, absent_message = _error_code(
        lambda: nfw.describe_rule_group(RuleGroupName=dry_name, Type="STATEFUL")
    )
    assert absent_code == "ResourceNotFoundException", "DryRun must not persist the rule group"
    assert absent_message == (
        "No object with the provided name or resource identifier was found"
    ), f"unexpected not-found message: {absent_message!r}"

    real_name = ctx.unique_name("sim2real-nfw-rg-real-")
    real_resp = nfw.create_rule_group(
        RuleGroupName=real_name, Type="STATEFUL", Capacity=expected_capacity, RuleGroup=rules,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    rule_group_arn = real_resp["RuleGroupResponse"]["RuleGroupArn"]
    ctx.on_cleanup(lambda: nfw.delete_rule_group(RuleGroupArn=rule_group_arn))

    assert real_resp["RuleGroupResponse"]["Capacity"] == expected_capacity, \
        f"expected create response Capacity {expected_capacity}, got {real_resp['RuleGroupResponse']['Capacity']}"

    desc = nfw.describe_rule_group(RuleGroupArn=rule_group_arn)
    consumed = desc["RuleGroupResponse"]["ConsumedCapacity"]
    assert consumed == expected_capacity, f"expected ConsumedCapacity == rule count {expected_capacity}, got {consumed}"
    assert consumed <= desc["RuleGroupResponse"]["Capacity"], \
        f"ConsumedCapacity {consumed} exceeds declared Capacity {desc['RuleGroupResponse']['Capacity']}"
    stateful_rules = desc["RuleGroup"]["RulesSource"]["StatefulRules"]
    assert len(stateful_rules) == 2, f"expected 2 stateful rules round-tripped, got {len(stateful_rules)}"


def _error_code(fn) -> tuple[str, str]:
    try:
        resp = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError, call unexpectedly succeeded with {resp!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
