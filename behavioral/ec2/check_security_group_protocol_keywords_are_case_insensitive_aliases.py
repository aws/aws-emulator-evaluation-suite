"""security-group-protocol-keywords-are-case-insensitive-aliases."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "security-group-protocol-keywords-are-case-insensitive-aliases"
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


def _shape(rules):
    """``_rules`` without the ids."""
    return [r[:5] for r in rules]


_PEER = "10.9.0.0/16"


def _ingress(protocol):
    return [{"IpProtocol": protocol, "FromPort": 0, "ToPort": 0, "IpRanges": [{"CidrIp": _PEER}]}]


@tags("axis:happy-path", "cap:c1", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Protocol keywords are case-insensitive aliases: "all" is stored as -1 with no ports, so "ALL"
    and "-1" are its duplicates, while "TCP" is stored as tcp keeping its 0/0 range.
    """
    ec2 = ctx.client("ec2")
    vpc_id = _vpc(ctx, ec2, "10.157.0.0/16")
    group_id = _group(ctx, ec2, vpc_id)

    granted = ec2.authorize_security_group_ingress(GroupId=group_id, IpPermissions=_ingress("all"))
    echoed = [(r["IpProtocol"], r["FromPort"], r["ToPort"], r["CidrIpv4"]) for r in granted["SecurityGroupRules"]]
    assert echoed == [("-1", -1, -1, _PEER)], f'protocol "all" must be stored as -1 ports -1, got {echoed!r}'
    for alias in ("ALL", "-1"):
        code, msg = _error(lambda: ec2.authorize_security_group_ingress(GroupId=group_id, IpPermissions=_ingress(alias)))
        want = ("InvalidPermission.Duplicate", f'the specified rule "peer: {_PEER}, ALL, ALLOW" already exists')
        assert (code, msg) == want, f'protocol {alias!r} after "all" must be {want!r}, got {(code, msg)!r}'

    granted = ec2.authorize_security_group_ingress(GroupId=group_id, IpPermissions=_ingress("TCP"))
    echoed = [(r["IpProtocol"], r["FromPort"], r["ToPort"], r["CidrIpv4"]) for r in granted["SecurityGroupRules"]]
    assert echoed == [("tcp", 0, 0, _PEER)], f'protocol "TCP" must be stored as tcp 0-0, got {echoed!r}'
    code, msg = _error(lambda: ec2.authorize_security_group_ingress(GroupId=group_id, IpPermissions=_ingress("Tcp")))
    want = ("InvalidPermission.Duplicate",
            f'the specified rule "peer: {_PEER}, TCP, from port: 0, to port: 0, ALLOW" already exists')
    assert (code, msg) == want, f'protocol "Tcp" after "TCP" must be {want!r}, got {(code, msg)!r}'

    assert _perms(ec2, group_id, "IpPermissions") == [("-1", None, None, (_PEER,)), ("tcp", 0, 0, (_PEER,))], (
        f"the group must hold exactly the -1 and tcp 0-0 rules, got {_perms(ec2, group_id, 'IpPermissions')!r}"
    )
    ingress = [r for r in _shape(_rules(ec2, group_id)) if not r[0]]
    assert ingress == [(False, "-1", -1, -1, _PEER), (False, "tcp", 0, 0, _PEER)], (
        f"DescribeSecurityGroupRules must agree, got {ingress!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
