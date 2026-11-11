"""delete-replication-group-wrong-state-rejected."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-replication-group-wrong-state-rejected"
GROUP = "negative-classes"
SERVICES = ["elasticache"]

_VPC_CIDR = "10.234.0.0/16"
_SUBNET_CIDR = "10.234.1.0/24"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteReplicationGroup on a 'creating' group is refused with InvalidReplicationGroupState
    and leaves it creating; once available the delete answers the group's id, description and
    status 'deleting', and the id then reads as not found."""
    ec = ctx.client("elasticache")
    subnet_group_name = _make_cache_subnet_group(ctx, "sim2real-ec-wrongstate-")

    rg_id = ctx.unique_name("sim2real-ec-wrongstate-")
    ec.create_replication_group(
        ReplicationGroupId=rg_id,
        ReplicationGroupDescription="sim2real behavioral wrong-state delete rg",
        Engine="redis",
        CacheNodeType="cache.t3.micro",
        NumCacheClusters=1,
        AutomaticFailoverEnabled=False,
        CacheSubnetGroupName=subnet_group_name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_replication_group_if_present(ctx, rg_id))

    # The create above holds the creating window for minutes. The refusal names the group's
    # first member cluster, which AWS ids as <ReplicationGroupId>-001.
    initial = ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"][0]
    assert initial["Status"] == "creating", f"expected the group to still be creating, got {initial['Status']!r}"
    refused = _error(lambda: ec.delete_replication_group(ReplicationGroupId=rg_id))
    assert refused == (
        "InvalidReplicationGroupState",
        f"Cache cluster {rg_id}-001 is not in a valid state to be deleted.",
    ), f"expected InvalidReplicationGroupState with its exact message, got {refused!r}"

    # Effect absent: the group is still present (not deleted / not transitioned to deleting).
    still_present = ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"][0]
    assert still_present["Status"] == "creating", (
        f"after the refused delete the group reads {still_present['Status']!r}, expected 'creating'"
    )

    # Positive control: once available, deletion is accepted.
    rg = _wait_rg_available(ctx, rg_id)
    assert rg["Status"] == "available", f"expected available, got {rg['Status']!r}"
    deleted = ec.delete_replication_group(ReplicationGroupId=rg_id)["ReplicationGroup"]
    got = (deleted["ReplicationGroupId"], deleted["Description"], deleted["Status"])
    want = (rg_id, "sim2real behavioral wrong-state delete rg", "deleting")
    assert got == want, f"DeleteReplicationGroup answered {got!r}, expected {want!r}"
    waiter = ec.get_waiter("replication_group_deleted")
    waiter.wait(ReplicationGroupId=rg_id, WaiterConfig={"Delay": 2, "MaxAttempts": 600})
    refused = _error(lambda: ec.describe_replication_groups(ReplicationGroupId=rg_id))
    assert refused == (
        "ReplicationGroupNotFoundFault",
        f"ReplicationGroup {rg_id} not found.",
    ), f"expected ReplicationGroupNotFoundFault with its exact message, got {refused!r}"

    # Gone is also unusable: a further mutation against the dead id fails the same way.
    refused = _error(lambda: ec.delete_replication_group(ReplicationGroupId=rg_id))
    assert refused == (
        "ReplicationGroupNotFoundFault",
        "Specified replication group does not exist",
    ), f"expected ReplicationGroupNotFoundFault with its exact message, got {refused!r}"




def _error(fn: Any) -> tuple[str | None, str | None]:
    """Call fn(); return the botocore Error (Code, Message). A SUCCESS raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_ec2_quietly(fn: Any, not_found_codes: tuple[str, ...]) -> None:
    try:
        fn()
    except ClientError as exc:
        if (exc.response.get("Error", {}).get("Code") or "") not in not_found_codes:
            raise


def _delete_subnet_group_quietly(ec: Any, name: str) -> None:
    try:
        ec.delete_cache_subnet_group(CacheSubnetGroupName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "CacheSubnetGroupNotFoundFault":
            raise


def _make_cache_subnet_group(ctx: Any, prefix: str) -> str:
    """Create a throwaway VPC, one subnet and a cache subnet group over it.

    The group never lands in an ambient default VPC. Cleanups run last-in first-out: the
    replication group (registered after this returns) is gone before the subnet group, subnet
    and VPC go.
    """
    ec2 = ctx.client("ec2")
    ec = ctx.client("elasticache")
    vpc_id = ec2.create_vpc(
        CidrBlock=_VPC_CIDR,
        TagSpecifications=[{
            "ResourceType": "vpc",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name(prefix + "vpc-")}],
        }],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(
        lambda: _delete_ec2_quietly(lambda: ec2.delete_vpc(VpcId=vpc_id), ("InvalidVpcID.NotFound",))
    )
    az = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    )[0]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock=_SUBNET_CIDR,
        AvailabilityZone=az,
        TagSpecifications=[{
            "ResourceType": "subnet",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name(prefix + "subnet-")}],
        }],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(
        lambda: _delete_ec2_quietly(
            lambda: ec2.delete_subnet(SubnetId=subnet_id), ("InvalidSubnetID.NotFound",)
        )
    )
    name = ctx.unique_name(prefix + "sng-")
    ec.create_cache_subnet_group(
        CacheSubnetGroupName=name,
        CacheSubnetGroupDescription="sim2real behavioral",
        SubnetIds=[subnet_id],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_subnet_group_quietly(ec, name))
    return name


def _rg_status(ec: Any, rg_id: str) -> str | None:
    try:
        groups = ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ReplicationGroupNotFoundFault":
            return None
        raise
    return groups[0]["Status"] if groups else None


def _wait_rg_available(ctx: Any, rg_id: str, timeout_s: float = 1500.0) -> dict:
    ec = ctx.client("elasticache")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        rg = ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"][0]
        last = rg
        if rg["Status"] == "available":
            return rg
        time.sleep(2)
    raise AssertionError(f"replication group {rg_id} never reached available, last={last}")


def _delete_replication_group_if_present(ctx: Any, rg_id: str, timeout_s: float = 1800.0) -> None:
    """Delete the group (tolerating one already deleting or gone) and wait until it is gone, so
    the subnet group registered before it can be deleted after it."""
    ec = ctx.client("elasticache")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = _rg_status(ec, rg_id)
        if status is None:
            return
        if status == "available":
            try:
                ec.delete_replication_group(ReplicationGroupId=rg_id)
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in (
                    "ReplicationGroupNotFoundFault", "InvalidReplicationGroupState"
                ):
                    raise
        time.sleep(15)
    raise AssertionError(f"replication group {rg_id} still present after {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
