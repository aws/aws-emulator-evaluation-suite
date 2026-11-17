"""security-group-reference-appears-with-active-peering-and-clears-on-revoke."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "security-group-reference-appears-with-active-peering-and-clears-on-revoke"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeSecurityGroupReferences names the peer VPC and the VPC peering connection once an
    active peering connection lets a rule reference a group in that peer VPC, and reports no
    reference again once the rule is revoked.
    """
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-sgref-")

    requester_vpc = _create_vpc_retrying(ec2, "10.214.0.0/16", name + "-req")
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=requester_vpc))
    accepter_vpc = _create_vpc_retrying(ec2, "10.215.0.0/16", name + "-acc")
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=accepter_vpc))
    ec2.get_waiter("vpc_available").wait(
        VpcIds=[requester_vpc, accepter_vpc], WaiterConfig={"Delay": 2, "MaxAttempts": 60}
    )

    referenced_group = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-sgref-target-"),
        Description="referenced across the peering connection",
        VpcId=accepter_vpc,
        TagSpecifications=[_tag_spec("security-group", name + "-target")],
    )["GroupId"]
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=referenced_group))

    referencing_group = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-sgref-source-"),
        Description="holds the rule that references the peer group",
        VpcId=requester_vpc,
        TagSpecifications=[_tag_spec("security-group", name + "-source")],
    )["GroupId"]
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=referencing_group))

    pcx_id = ec2.create_vpc_peering_connection(
        VpcId=requester_vpc,
        PeerVpcId=accepter_vpc,
        TagSpecifications=[_tag_spec("vpc-peering-connection", name)],
    )["VpcPeeringConnection"]["VpcPeeringConnectionId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc_peering_connection(VpcPeeringConnectionId=pcx_id))
    ec2.accept_vpc_peering_connection(VpcPeeringConnectionId=pcx_id)
    _poll_until(
        lambda: ec2.describe_vpc_peering_connections(VpcPeeringConnectionIds=[pcx_id])[
            "VpcPeeringConnections"
        ][0]["Status"]["Code"],
        lambda code: code == "active",
        timeout_s=60,
        interval_s=3,
    )

    # Before any rule references it, the target group carries no recorded reference.
    before = ec2.describe_security_group_references(GroupId=[referenced_group])[
        "SecurityGroupReferenceSet"
    ]
    assert before == [], f"expected no references before any rule exists, got {before!r}"

    perm = {
        "IpProtocol": "tcp",
        "FromPort": 443,
        "ToPort": 443,
        "UserIdGroupPairs": [{"GroupId": referenced_group}],
    }
    ec2.authorize_security_group_ingress(GroupId=referencing_group, IpPermissions=[perm])
    revoked = {"done": False}

    def _revoke_if_needed() -> None:
        if not revoked["done"]:
            ec2.revoke_security_group_ingress(GroupId=referencing_group, IpPermissions=[perm])

    ctx.on_cleanup(_revoke_if_needed)

    after = _poll_until(
        lambda: ec2.describe_security_group_references(GroupId=[referenced_group])[
            "SecurityGroupReferenceSet"
        ],
        lambda refs: refs != [],
        timeout_s=60,
        interval_s=3,
    )
    assert len(after) == 1, f"expected exactly one reference, got {after!r}"
    entry = after[0]
    assert entry["GroupId"] == referenced_group, (
        f"expected GroupId {referenced_group!r}, got {entry['GroupId']!r}"
    )
    assert entry["ReferencingVpcId"] == requester_vpc, (
        f"expected ReferencingVpcId {requester_vpc!r}, got {entry['ReferencingVpcId']!r}"
    )
    assert entry["VpcPeeringConnectionId"] == pcx_id, (
        f"expected VpcPeeringConnectionId {pcx_id!r}, got {entry['VpcPeeringConnectionId']!r}"
    )

    ec2.revoke_security_group_ingress(GroupId=referencing_group, IpPermissions=[perm])
    revoked["done"] = True

    cleared = _poll_until(
        lambda: ec2.describe_security_group_references(GroupId=[referenced_group])[
            "SecurityGroupReferenceSet"
        ],
        lambda refs: refs == [],
        timeout_s=60,
        interval_s=3,
    )
    assert cleared == [], f"expected the reference to clear after revoke, got {cleared!r}"


def _tag_spec(resource_type: str, value: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": value}]}


def _create_vpc_retrying(ec2, cidr: str, name: str, *, timeout_s: float = 180.0, interval_s: float = 10.0) -> str:
    """Create a VPC, retrying through a transient VpcLimitExceeded from sibling checks sharing the account."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return ec2.create_vpc(CidrBlock=cidr, TagSpecifications=[_tag_spec("vpc", name)])["Vpc"]["VpcId"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "VpcLimitExceeded" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last saw {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
