"""security-group-all-protocols-egress-revoke-ignores-the-port-range."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "security-group-all-protocols-egress-revoke-ignores-the-port-range"
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


#: Port ranges a revoke may carry beside protocol -1; AWS ignores every one of them.
_PORTS = [(-1, -1), (0, 0), (22, 22), (0, 65535), (5, 1)]


@tags("axis:happy-path", "cap:c1", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A protocol -1 revoke matches the implicit allow-all egress rule whatever port range it carries:
    -1/-1, 0/0, 22/22, 0/65535 and even an inverted 5/1 each remove it, only from the named group,
    and the same revoke again is InvalidPermission.NotFound."""
    ec2 = ctx.client("ec2")
    vpc_id = _vpc(ctx, ec2, "10.153.0.0/16")
    groups = [_group(ctx, ec2, vpc_id) for _ in _PORTS]
    bystander = _group(ctx, ec2, vpc_id)

    for group_id, (from_port, to_port) in zip(groups, _PORTS):
        implicit = _rules(ec2, group_id)
        assert _key(implicit) == [(True, "-1", "0.0.0.0/0")], (
            f"a new group must hold exactly the implicit egress rule, got {_key(implicit)!r}"
        )
        permission = {"IpProtocol": "-1", "FromPort": from_port, "ToPort": to_port,
                      "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
        revoked = ec2.revoke_security_group_egress(GroupId=group_id, IpPermissions=[permission])
        assert revoked.get("Return") is True, (
            f"revoking -1 with ports {from_port}/{to_port} must Return true, got {revoked!r}"
        )
        assert revoked.get("UnknownIpPermissions", []) == [], (
            f"revoking -1 with ports {from_port}/{to_port} must match the implicit rule, got unknown "
            f"{revoked.get('UnknownIpPermissions')!r}"
        )
        ids = [r["SecurityGroupRuleId"] for r in revoked["RevokedSecurityGroupRules"]]
        assert ids == [implicit[0][5]], (
            f"revoking -1 with ports {from_port}/{to_port} must remove the implicit rule "
            f"{implicit[0][5]!r}, revoked {ids!r}"
        )
        assert _rules(ec2, group_id) == [], (
            f"after revoking -1 with ports {from_port}/{to_port} the group must have no rules, "
            f"got {_key(_rules(ec2, group_id))!r}"
        )
        code, msg = _error(lambda: ec2.revoke_security_group_egress(
            GroupId=group_id, IpPermissions=[permission]))
        assert (code, msg) == (
            "InvalidPermission.NotFound", "The specified rule does not exist in this security group."
        ), f"revoking -1 with ports {from_port}/{to_port} again must be InvalidPermission.NotFound, got {(code, msg)!r}"

    # Control: a group no revoke named keeps its implicit rule.
    assert _key(_rules(ec2, bystander)) == [(True, "-1", "0.0.0.0/0")], (
        f"an untouched group must keep its implicit egress rule, got {_key(_rules(ec2, bystander))!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
