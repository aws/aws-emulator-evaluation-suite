"""security-group-rule-id-revoke-across-direction-or-group-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "security-group-rule-id-revoke-across-direction-or-group-rejected"
GROUP = "security-group"
SERVICES = ["ec2"]

_TAG = [{"Key": "sim2real", "Value": "1"}]


def _error(fn):
    """The (code, message) of the ClientError ``fn`` raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` that returns only on the resource's own not-found codes."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _vpc(ctx, ec2, cidr):
    vpc_id = ec2.create_vpc(
        CidrBlock=cidr, TagSpecifications=[{"ResourceType": "vpc", "Tags": _TAG}]
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(_teardown(lambda: ec2.delete_vpc(VpcId=vpc_id), "InvalidVpcID.NotFound"))
    deadline = time.monotonic() + 90
    state = None
    while time.monotonic() < deadline:
        state = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"]
        if state == "available":
            return vpc_id
        time.sleep(2)
    raise AssertionError(f"the VPC never reached available in 90s (last {state!r})")


def _group(ctx, ec2, vpc_id):
    group_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-sg-"),
        Description="sim2real security group rule forms",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _TAG}],
    )["GroupId"]
    ctx.on_cleanup(_teardown(lambda: ec2.delete_security_group(GroupId=group_id), "InvalidGroup.NotFound"))
    return group_id


def _perms(ec2, group_id, key):
    """``key`` (IpPermissions or IpPermissionsEgress) as (protocol, from, to, cidrs) tuples."""
    group = ec2.describe_security_groups(GroupIds=[group_id])["SecurityGroups"][0]
    return sorted(
        (p["IpProtocol"], p.get("FromPort"), p.get("ToPort"), tuple(sorted(r["CidrIp"] for r in p["IpRanges"])))
        for p in group[key]
    )


def _rules(ec2, group_id):
    """The group's rules as (is_egress, protocol, from, to, cidr, id) tuples."""
    pages = ec2.get_paginator("describe_security_group_rules").paginate(
        Filters=[{"Name": "group-id", "Values": [group_id]}]
    )
    return sorted(
        ((r["IsEgress"], r["IpProtocol"], r.get("FromPort"), r.get("ToPort"), r.get("CidrIpv4"), r["SecurityGroupRuleId"])
         for page in pages for r in page["SecurityGroupRules"]),
        key=lambda r: tuple(str(x) for x in r),
    )


def _key(rules):
    """``_rules`` as (is_egress, protocol, cidr) tuples, without ports or ids."""
    return [(r[0], r[1], r[4]) for r in rules]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The implicit egress rule is revoked by its sgr- id; that id is then unknown, an egress id is
    refused by RevokeSecurityGroupIngress, and another group's id is not found in this group.
    """
    ec2 = ctx.client("ec2")
    vpc_id = _vpc(ctx, ec2, "10.156.0.0/16")
    group_id = _group(ctx, ec2, vpc_id)
    other_id = _group(ctx, ec2, vpc_id)
    own_rule = _rules(ec2, group_id)
    assert _key(own_rule) == [(True, "-1", "0.0.0.0/0")], (
        f"the first group must hold only its implicit egress rule, got {_key(own_rule)!r}"
    )
    rule_id = own_rule[0][5]
    other_rule = _rules(ec2, other_id)
    assert _key(other_rule) == [(True, "-1", "0.0.0.0/0")], (
        f"the second group must hold only its implicit egress rule, got {_key(other_rule)!r}"
    )
    other_rule_id = other_rule[0][5]

    # An egress rule id named in an ingress revoke is refused and the rule stays.
    code, msg = _error(lambda: ec2.revoke_security_group_ingress(GroupId=other_id, SecurityGroupRuleIds=[other_rule_id]))
    want = ("InvalidParameterValue",
            f"The security group rule ID '{other_rule_id}' is an egress rule and may not be specified "
            "in a revoke-security-group-ingress request.")
    assert (code, msg) == want, f"revoking an egress rule id as ingress must be {want!r}, got {(code, msg)!r}"
    assert _rules(ec2, other_id) == other_rule, (
        f"the refused ingress revoke must leave the egress rule, got {_rules(ec2, other_id)!r}"
    )

    # Another group's rule id is not a rule of this group.
    code, msg = _error(lambda: ec2.revoke_security_group_egress(GroupId=group_id, SecurityGroupRuleIds=[other_rule_id]))
    want = ("InvalidSecurityGroupRuleId.NotFound", f"The security group rule ID '{other_rule_id}' does not exist")
    assert (code, msg) == want, f"revoking another group's rule id must be {want!r}, got {(code, msg)!r}"
    assert _rules(ec2, other_id) == other_rule, (
        f"a revoke naming another group must not touch this rule, got {_rules(ec2, other_id)!r}"
    )

    # Control: the group's own id revokes its implicit rule.
    revoked = ec2.revoke_security_group_egress(GroupId=group_id, SecurityGroupRuleIds=[rule_id])
    assert revoked.get("Return") is True, f"revoking by rule id must Return true, got {revoked!r}"
    echoed = [(r["SecurityGroupRuleId"], r["IsEgress"], r["IpProtocol"], r["CidrIpv4"])
              for r in revoked["RevokedSecurityGroupRules"]]
    assert echoed == [(rule_id, True, "-1", "0.0.0.0/0")], f"the revoke must echo the implicit rule, got {echoed!r}"
    assert _perms(ec2, group_id, "IpPermissionsEgress") == [], (
        f"no egress may remain, got {_perms(ec2, group_id, 'IpPermissionsEgress')!r}"
    )

    code, msg = _error(lambda: ec2.revoke_security_group_egress(GroupId=group_id, SecurityGroupRuleIds=[rule_id]))
    want = ("InvalidSecurityGroupRuleId.NotFound", f"The security group rule ID '{rule_id}' does not exist")
    assert (code, msg) == want, f"revoking a revoked rule id must be {want!r}, got {(code, msg)!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
