"""security-group-all-protocols-ingress-revokes-across-port-forms."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "security-group-all-protocols-ingress-revokes-across-port-forms"
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
    """``_rules`` as (is_egress, protocol, cidr, id) tuples, without ports."""
    return sorted((r[0], r[1], r[4], r[5]) for r in rules)


_PEER = "10.0.0.0/8"
_ZERO = {"IpProtocol": "-1", "FromPort": 0, "ToPort": 0, "IpRanges": [{"CidrIp": _PEER}]}
_PORTLESS = {"IpProtocol": "-1", "IpRanges": [{"CidrIp": _PEER}]}


@tags("axis:happy-path", "cap:c1", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An all-protocols ingress rule is one rule whichever port form wrote it: authorized with ports
    0/0 it is revoked port-less, and authorized port-less it is revoked with ports 0/0.
    """
    ec2 = ctx.client("ec2")
    vpc_id = _vpc(ctx, ec2, "10.155.0.0/16")
    group_id = _group(ctx, ec2, vpc_id)
    implicit = _rules(ec2, group_id)
    assert [r[:3] for r in _key(implicit)] == [(True, "-1", "0.0.0.0/0")], (
        f"a new group must hold only the implicit egress rule, got {_key(implicit)!r}"
    )

    for written, revoked_as, label in ((_ZERO, _PORTLESS, "0/0 then port-less"),
                                       (_PORTLESS, _ZERO, "port-less then 0/0")):
        granted = ec2.authorize_security_group_ingress(GroupId=group_id, IpPermissions=[written])
        assert granted.get("Return") is True, f"[{label}] the authorize must Return true, got {granted!r}"
        rule_id = granted["SecurityGroupRules"][0]["SecurityGroupRuleId"]
        assert _perms(ec2, group_id, "IpPermissions") == [("-1", None, None, (_PEER,))], (
            f"[{label}] the ingress rule must be stored port-less, got {_perms(ec2, group_id, 'IpPermissions')!r}"
        )
        assert _key(_rules(ec2, group_id)) == sorted(_key(implicit) + [(False, "-1", _PEER, rule_id)]), (
            f"[{label}] the rule view must add one ingress rule, got {_key(_rules(ec2, group_id))!r}"
        )

        revoked = ec2.revoke_security_group_ingress(GroupId=group_id, IpPermissions=[revoked_as])
        assert revoked.get("Return") is True, f"[{label}] the cross-form revoke must Return true, got {revoked!r}"
        ids = [r["SecurityGroupRuleId"] for r in revoked["RevokedSecurityGroupRules"]]
        assert ids == [rule_id], f"[{label}] the revoke must remove rule {rule_id!r}, removed {ids!r}"
        assert _perms(ec2, group_id, "IpPermissions") == [], (
            f"[{label}] no ingress may remain, got {_perms(ec2, group_id, 'IpPermissions')!r}"
        )

    # The implicit egress rule, also protocol -1, was never matched by an ingress revoke.
    assert _rules(ec2, group_id) == implicit, (
        f"the ingress revokes must leave the implicit egress rule alone, got {_rules(ec2, group_id)!r}"
    )
    code, msg = _error(lambda: ec2.revoke_security_group_ingress(GroupId=group_id, IpPermissions=[_ZERO]))
    assert (code, msg) == (
        "InvalidPermission.NotFound", "The specified rule does not exist in this security group."
    ), f"revoking the removed ingress rule again must be InvalidPermission.NotFound, got {(code, msg)!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
