"""op-contract-describeSecurityGroupRules."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeSecurityGroupRules"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeSecurityGroupRules returns a new group's single default egress rule to 0.0.0.0/0, finds the
    same rule by SecurityGroupRuleIds, and fails a well-formed unknown rule ID with
    InvalidSecurityGroupRuleId.NotFound and its exact message."""
    ec2 = ctx.client("ec2")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.201.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    group_name = ctx.unique_name("sim2real-behav-sgrules-")
    group_id = ec2.create_security_group(
        GroupName=group_name,
        Description="sim2real behavioral check: security group rules",
        VpcId=vpc_id,
        TagSpecifications=[
            {
                "ResourceType": "security-group",
                "Tags": [{"Key": "Name", "Value": group_name}],
            }
        ],
    )["GroupId"]
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=group_id))

    resp = ec2.describe_security_group_rules(Filters=[{"Name": "group-id", "Values": [group_id]}])
    rules = resp["SecurityGroupRules"]
    assert len(rules) == 1, f"a fresh security group must have exactly the one default egress rule, got {rules!r}"
    default_egress = rules[0]
    assert default_egress.get("IsEgress") is True, f"the sole rule must be egress, got {default_egress!r}"
    assert default_egress["GroupId"] == group_id, (
        f"rule {default_egress.get('SecurityGroupRuleId')!r} points at group "
        f"{default_egress['GroupId']!r}, expected {group_id!r}"
    )
    assert default_egress.get("CidrIpv4") == "0.0.0.0/0", f"unexpected default egress rule: {default_egress!r}"

    # positive control: the id-based lookup path (SecurityGroupRuleIds) works for a real id,
    # so the NotFound test below cannot be "rejects every lookup on this path".
    rule_id = default_egress["SecurityGroupRuleId"]
    by_id = ec2.describe_security_group_rules(SecurityGroupRuleIds=[rule_id])["SecurityGroupRules"]
    assert len(by_id) == 1 and by_id[0]["SecurityGroupRuleId"] == rule_id, (
        f"describing the real rule {rule_id!r} via SecurityGroupRuleIds must return exactly it, got {by_id!r}"
    )

    code, message = _client_error(
        lambda: ec2.describe_security_group_rules(SecurityGroupRuleIds=["sgr-0123456789abcdef0"])
    )
    assert code == "InvalidSecurityGroupRuleId.NotFound", f"expected InvalidSecurityGroupRuleId.NotFound, got {code!r}"
    expected_message = "The security group rule ID 'sgr-0123456789abcdef0' does not exist"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _client_error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError but the call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
