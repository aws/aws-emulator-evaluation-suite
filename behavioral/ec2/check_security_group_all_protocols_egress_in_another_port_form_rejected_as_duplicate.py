"""security-group-all-protocols-egress-in-another-port-form-rejected-as-duplicate."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "security-group-all-protocols-egress-in-another-port-form-rejected-as-duplicate"
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
        (r["IsEgress"], r["IpProtocol"], r.get("FromPort"), r.get("ToPort"), r.get("CidrIpv4"), r["SecurityGroupRuleId"])
        for page in pages for r in page["SecurityGroupRules"]
    )


_PEER = "10.0.0.0/8"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Egress authorized as protocol -1 with ports 0/0 is stored port-less (ports -1 in the rule view),
    so the same rule written port-less, as -1/-1 or as 22/22 is rejected InvalidPermission.Duplicate.
    """
    ec2 = ctx.client("ec2")
    vpc_id = _vpc(ctx, ec2, "10.154.0.0/16")
    group_id = _group(ctx, ec2, vpc_id)
    ec2.revoke_security_group_egress(
        GroupId=group_id, IpPermissions=[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]
    )
    assert _rules(ec2, group_id) == [], f"the group must start empty, got {_rules(ec2, group_id)!r}"

    granted = ec2.authorize_security_group_egress(
        GroupId=group_id,
        IpPermissions=[{"IpProtocol": "-1", "FromPort": 0, "ToPort": 0, "IpRanges": [{"CidrIp": _PEER}]}],
    )
    assert granted.get("Return") is True, f"authorizing -1 with ports 0/0 must Return true, got {granted!r}"
    echoed = [
        (r["GroupOwnerId"], r["IsEgress"], r["IpProtocol"], r["FromPort"], r["ToPort"], r["CidrIpv4"])
        for r in granted["SecurityGroupRules"]
    ]
    assert echoed == [(ctx.account, True, "-1", -1, -1, _PEER)], (
        f"the authorize must echo the rule with ports normalized to -1, got {echoed!r}"
    )
    rule_id = granted["SecurityGroupRules"][0]["SecurityGroupRuleId"]

    assert _perms(ec2, group_id, "IpPermissionsEgress") == [("-1", None, None, (_PEER,))], (
        "DescribeSecurityGroups must store the -1 rule with no FromPort/ToPort, got "
        f"{_perms(ec2, group_id, 'IpPermissionsEgress')!r}"
    )
    assert _rules(ec2, group_id) == [(True, "-1", -1, -1, _PEER, rule_id)], (
        f"DescribeSecurityGroupRules must list the one rule with ports -1, got {_rules(ec2, group_id)!r}"
    )

    for label, ports in (("port-less", {}), ("-1/-1", {"FromPort": -1, "ToPort": -1}),
                         ("22/22", {"FromPort": 22, "ToPort": 22})):
        code, msg = _error(lambda: ec2.authorize_security_group_egress(
            GroupId=group_id, IpPermissions=[{"IpProtocol": "-1", **ports, "IpRanges": [{"CidrIp": _PEER}]}]
        ))
        assert (code, msg) == (
            "InvalidPermission.Duplicate", f'the specified rule "peer: {_PEER}, ALL, ALLOW" already exists'
        ), f"re-authorizing the -1 rule {label} must be InvalidPermission.Duplicate, got {(code, msg)!r}"

    assert _rules(ec2, group_id) == [(True, "-1", -1, -1, _PEER, rule_id)], (
        f"the refused duplicates must leave exactly the original rule, got {_rules(ec2, group_id)!r}"
    )
    assert _perms(ec2, group_id, "IpPermissions") == [], "an egress authorize must not add ingress"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
