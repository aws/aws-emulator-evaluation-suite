"""security-group-default-egress-and-rule-ids."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "security-group-default-egress-and-rule-ids"
GROUP = 'security-group'
SERVICES = ['ec2']

_RULE_ID = re.compile(r"sgr-[0-9a-f]{17}")
VPC_CIDR = '10.144.0.0/16'
#: The implicit allow-all IPv4 egress rule, as RevokeSecurityGroupEgress names it.
_OPEN_EGRESS = [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]

def _error(fn):
    """The (code, message) of the ClientError ``fn`` raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _rule_fields(rule):
    """The fields a rule's direction, protocol, ports, peer and owner are read from."""
    keys = ("GroupId", "GroupOwnerId", "IsEgress", "IpProtocol", "FromPort", "ToPort", "CidrIpv4")
    return {k: rule.get(k) for k in keys}


def _wait_vpc_available(ec2, vpc_id, timeout_s=90):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"]
        if last == "available":
            return
        time.sleep(2)
    raise AssertionError(f"vpc {vpc_id} never reached available in {timeout_s}s (last {last!r})")


def _sg(ec2, group_id):
    return ec2.describe_security_groups(GroupIds=[group_id])["SecurityGroups"][0]


def _rules(ec2, group_id):
    return ec2.describe_security_group_rules(
        Filters=[{"Name": "group-id", "Values": [group_id]}]
    ).get("SecurityGroupRules", [])


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A new security group has one implicit allow-all IPv4 egress rule, ports -1, with an sgr- id and
    no ingress; revoking it empties egress, revoking it again is refused with an exact message, and an
    explicit tcp egress rule is echoed exactly while its duplicate is refused InvalidPermission.Duplicate.
    """
    ec2 = ctx.client("ec2")
    tag = [{"Key": "sim2real", "Value": "1"}]

    # An own VPC, so the "exactly one rule" claim cannot depend on the account's default VPC.
    vpc_id = ec2.create_vpc(
        CidrBlock=VPC_CIDR, TagSpecifications=[{"ResourceType": "vpc", "Tags": tag}]
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    _wait_vpc_available(ec2, vpc_id)

    group_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-sg-"),
        Description="sim2real default egress check",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": tag}],
    )["GroupId"]
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=group_id))

    # --- the implicit default: one allow-all egress rule, zero ingress ---
    fresh = _sg(ec2, group_id)
    assert fresh["IpPermissions"] == [], (
        f"a new security group must have NO ingress rules, got {fresh['IpPermissions']}"
    )
    egress = fresh["IpPermissionsEgress"]
    assert len(egress) == 1, (
        f"a new security group must have exactly ONE implicit egress rule, got {egress}"
    )
    rule = egress[0]
    assert rule["IpProtocol"] == "-1", (
        f"the implicit egress rule must be all-protocols ('-1'), got {rule['IpProtocol']!r}"
    )
    assert [r["CidrIp"] for r in rule.get("IpRanges", [])] == ["0.0.0.0/0"], (
        f"the implicit egress rule must allow 0.0.0.0/0, got {rule.get('IpRanges')}"
    )
    assert "FromPort" not in rule and "ToPort" not in rule, (
        f"an all-protocols rule carries no port range, got {rule}"
    )

    # --- the implicit rule is a first-class object with an id ---
    listed = _rules(ec2, group_id)
    assert len(listed) == 1, (
        f"DescribeSecurityGroupRules must report exactly the one implicit rule, got {listed}"
    )
    implicit = listed[0]
    assert implicit["IsEgress"] is True, f"the implicit rule must be IsEgress=True, got {implicit}"
    assert implicit["GroupId"] == group_id, (
        f"rule {implicit.get('SecurityGroupRuleId')} points at group {implicit.get('GroupId')!r}, expected {group_id}"
    )
    assert _RULE_ID.fullmatch(implicit.get("SecurityGroupRuleId", "")), (
        f"every security group rule must carry an sgr- id, got {implicit.get('SecurityGroupRuleId')!r}"
    )
    want_implicit = {
        "GroupId": group_id, "GroupOwnerId": ctx.account, "IsEgress": True, "IpProtocol": "-1",
        "FromPort": -1, "ToPort": -1, "CidrIpv4": "0.0.0.0/0",
    }
    assert _rule_fields(implicit) == want_implicit, (
        f"the implicit egress rule reads back as {_rule_fields(implicit)}, expected {want_implicit}"
    )

    # --- revoking the implicit rule is real and observable ---
    revoked = ec2.revoke_security_group_egress(GroupId=group_id, IpPermissions=_OPEN_EGRESS)
    assert revoked.get("Return") is True, f"RevokeSecurityGroupEgress must Return true, got {revoked}"
    assert _sg(ec2, group_id)["IpPermissionsEgress"] == [], (
        "after revoking the implicit rule the group must have ZERO egress rules "
        f"(got {_sg(ec2, group_id)['IpPermissionsEgress']})"
    )
    assert _rules(ec2, group_id) == [], (
        f"DescribeSecurityGroupRules must be empty after the revoke, got {_rules(ec2, group_id)}"
    )

    # --- break exactly one thing: revoke the same rule again ---
    code, msg = _error(lambda: ec2.revoke_security_group_egress(GroupId=group_id, IpPermissions=_OPEN_EGRESS))
    assert (code, msg) == (
        "InvalidPermission.NotFound",
        "The specified rule does not exist in this security group.",
    ), f"revoking an already-revoked egress rule answered {(code, msg)}"
    # effect absent: the failed revoke did not resurrect or invent a rule
    assert _sg(ec2, group_id)["IpPermissionsEgress"] == [], (
        "the rejected second revoke must leave the egress list empty"
    )

    # --- control: an explicit narrow egress rule can be added back and is reported with an id ---
    https_egress = [
        {
            "IpProtocol": "tcp",
            "FromPort": 443,
            "ToPort": 443,
            "IpRanges": [{"CidrIp": "10.0.0.0/8", "Description": "sim2real https egress"}],
        }
    ]
    added = ec2.authorize_security_group_egress(GroupId=group_id, IpPermissions=https_egress)
    assert added.get("Return") is True, f"AuthorizeSecurityGroupEgress must Return true, got {added}"
    echoed = added["SecurityGroupRules"]
    assert len(echoed) == 1, f"the authorize response must echo exactly one rule, got {echoed}"
    want_https = {
        "GroupId": group_id, "GroupOwnerId": ctx.account, "IsEgress": True, "IpProtocol": "tcp",
        "FromPort": 443, "ToPort": 443, "CidrIpv4": "10.0.0.0/8",
    }
    assert _rule_fields(echoed[0]) == want_https, (
        f"the authorize response echoes {_rule_fields(echoed[0])}, expected {want_https}"
    )
    assert echoed[0]["Description"] == "sim2real https egress", (
        f"the echoed rule carries description {echoed[0].get('Description')!r}"
    )
    assert _RULE_ID.fullmatch(echoed[0]["SecurityGroupRuleId"]), (
        f"the echoed rule id is {echoed[0]['SecurityGroupRuleId']!r}"
    )
    final = _sg(ec2, group_id)["IpPermissionsEgress"]
    assert len(final) == 1, f"expected exactly the one explicit egress rule, got {final}"
    assert final[0]["IpProtocol"] == "tcp", f"expected protocol tcp, got {final[0]['IpProtocol']!r}"
    assert final[0]["FromPort"] == 443 and final[0]["ToPort"] == 443, (
        f"expected the 443..443 port range, got {final[0].get('FromPort')}..{final[0].get('ToPort')}"
    )
    assert [r["CidrIp"] for r in final[0]["IpRanges"]] == ["10.0.0.0/8"], (
        f"expected the 10.0.0.0/8 range, got {final[0]['IpRanges']}"
    )
    final_rules = _rules(ec2, group_id)
    assert len(final_rules) == 1, f"the explicit rule must be the only rule listed, got {final_rules}"
    assert final_rules[0]["SecurityGroupRuleId"] == echoed[0]["SecurityGroupRuleId"], (
        f"DescribeSecurityGroupRules lists {final_rules[0]['SecurityGroupRuleId']!r}, the authorize "
        f"response returned {echoed[0]['SecurityGroupRuleId']!r}"
    )
    assert _rule_fields(final_rules[0]) == want_https, (
        f"the explicit rule reads back as {_rule_fields(final_rules[0])}, expected {want_https}"
    )
    assert final_rules[0]["SecurityGroupRuleId"] != implicit["SecurityGroupRuleId"], (
        "a newly authorized rule must get a NEW rule id, not reuse the revoked rule's id"
    )
    # --- break exactly one thing: authorize the identical egress rule again ---
    code, msg = _error(lambda: ec2.authorize_security_group_egress(GroupId=group_id, IpPermissions=https_egress))
    assert (code, msg) == (
        "InvalidPermission.Duplicate",
        'the specified rule "peer: 10.0.0.0/8, TCP, from port: 443, to port: 443, ALLOW" already exists',
    ), f"authorizing a duplicate egress rule answered {(code, msg)}"
    after_dup = _rules(ec2, group_id)
    assert [r["SecurityGroupRuleId"] for r in after_dup] == [echoed[0]["SecurityGroupRuleId"]], (
        f"the refused duplicate must leave exactly the one rule, got {after_dup}"
    )
    # --- restore: once the original is revoked, the identical call is accepted again ---
    ec2.revoke_security_group_egress(GroupId=group_id, IpPermissions=https_egress)
    restored = ec2.authorize_security_group_egress(GroupId=group_id, IpPermissions=https_egress)
    assert restored.get("Return") is True, (
        f"the identical egress rule must be authorizable again once the duplicate is revoked, got {restored}"
    )
    restored_rules = _rules(ec2, group_id)
    assert len(restored_rules) == 1, (
        f"expected exactly the one restored egress rule, got {restored_rules}"
    )
    assert _rule_fields(restored_rules[0]) == want_https, (
        f"the restored rule reads back as {_rule_fields(restored_rules[0])}, expected {want_https}"
    )
    # the ingress side stayed empty throughout: authorize_egress must not leak into ingress
    assert _sg(ec2, group_id)["IpPermissions"] == [], (
        "authorizing EGRESS must not create an ingress rule"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
