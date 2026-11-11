"""security-group-unknown-protocol-or-icmpv6-zero-ports-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "security-group-unknown-protocol-or-icmpv6-zero-ports-rejected"
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


_PEER = "10.9.0.0/16"


def _ingress(protocol):
    return [{"IpProtocol": protocol, "FromPort": 0, "ToPort": 0, "IpRanges": [{"CidrIp": _PEER}]}]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A protocol outside 0-255 or a name other than tcp/udp/icmp/icmpv6/all is rejected, and icmpv6
    refuses ports 0/0; numbered protocols such as 50 and 132 are accepted with their ports dropped.
    """
    ec2 = ctx.client("ec2")
    vpc_id = _vpc(ctx, ec2, "10.158.0.0/16")
    group_id = _group(ctx, ec2, vpc_id)

    for protocol in ("esp", "256", "-2"):
        code, msg = _error(lambda: ec2.authorize_security_group_ingress(GroupId=group_id, IpPermissions=_ingress(protocol)))
        want = ("InvalidParameterValue", f"Invalid value '{protocol}' for IP protocol. Unknown protocol.")
        assert (code, msg) == want, f"protocol {protocol!r} must be refused {want!r}, got {(code, msg)!r}"
    icmpv6_msg = ("When protocol is 58 and remote-ip-range is specified, port range must either not be "
                  "specified or must be specified as from=-1 and to=-1.")
    for protocol in ("icmpv6", "58"):
        code, msg = _error(lambda: ec2.authorize_security_group_ingress(GroupId=group_id, IpPermissions=_ingress(protocol)))
        assert (code, msg) == ("InvalidParameterValue", icmpv6_msg), (
            f"protocol {protocol!r} with ports 0/0 must be refused {icmpv6_msg!r}, got {(code, msg)!r}"
        )
    assert _perms(ec2, group_id, "IpPermissions") == [], (
        f"the refused authorizes must add no ingress, got {_perms(ec2, group_id, 'IpPermissions')!r}"
    )

    # Control: numbered protocols other than tcp/udp/icmp/icmpv6 are accepted and carry no ports.
    for protocol in ("50", "132"):
        granted = ec2.authorize_security_group_ingress(GroupId=group_id, IpPermissions=_ingress(protocol))
        echoed = [(r["IpProtocol"], r["FromPort"], r["ToPort"]) for r in granted["SecurityGroupRules"]]
        assert echoed == [(protocol, -1, -1)], f"protocol {protocol!r} must be stored with ports -1, got {echoed!r}"
    assert _perms(ec2, group_id, "IpPermissions") == [("132", None, None, (_PEER,)), ("50", None, None, (_PEER,))], (
        f"the group must hold exactly the 50 and 132 rules, port-less, got {_perms(ec2, group_id, 'IpPermissions')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
