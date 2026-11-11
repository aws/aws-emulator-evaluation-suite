"""modify-replication-group-invalid-node-type-rejected."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "modify-replication-group-invalid-node-type-rejected"
GROUP = "negative-classes"
SERVICES = ["elasticache"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyReplicationGroup with a nonexistent CacheNodeType is rejected with InvalidParameterValue and its
    exact message and changes neither the node type nor the pending values, while cache.t3.small is then
    applied."""
    ec = ctx.client("elasticache")
    vpc_id = _default_vpc_id(ctx)
    subnet_ids = _subnet_ids(ctx, vpc_id, count=2)
    subnet_group_name = _create_subnet_group(ctx, subnet_ids)

    rg_id = ctx.unique_name("sim2real-ec-badnodetype-")
    ec.create_replication_group(
        ReplicationGroupId=rg_id,
        ReplicationGroupDescription="sim2real behavioral invalid-node-type rg",
        Engine="redis",
        CacheNodeType="cache.t3.micro",
        NumCacheClusters=1,
        AutomaticFailoverEnabled=False,
        CacheSubnetGroupName=subnet_group_name,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_replication_group(ctx, rg_id))
    rg = _wait_rg_available(ctx, rg_id)
    assert rg["CacheNodeType"] == "cache.t3.micro", rg["CacheNodeType"]

    code, message = _error_code(
        lambda: ec.modify_replication_group(
            ReplicationGroupId=rg_id, CacheNodeType="cache.bogus.doesnotexist", ApplyImmediately=True
        )
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}"
    expected = "Invalid Cache Node Type: cache.bogus.doesnotexist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: node type unchanged, no pending modification queued either.
    rg = ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"][0]
    assert rg["CacheNodeType"] == "cache.t3.micro", rg["CacheNodeType"]
    pending = rg.get("PendingModifiedValues", {})
    assert not pending.get("CacheNodeType"), pending

    # Positive control: a real, valid node type is accepted and eventually applied.
    ec.modify_replication_group(ReplicationGroupId=rg_id, CacheNodeType="cache.t3.small", ApplyImmediately=True)
    # A node-type change replaces the node, which takes longer than the create.
    rg = _wait_rg_available(ctx, rg_id, timeout_s=1800.0)
    assert rg["CacheNodeType"] == "cache.t3.small", rg["CacheNodeType"]


# ===== helpers =====


def _default_vpc_id(ctx: Any) -> str:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    return vpcs[0]["VpcId"]


def _subnet_ids(ctx: Any, vpc_id: str, count: int = 2) -> list[str]:
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if len(subnets) < count:
        raise AssertionError(f"fewer than {count} subnets available in VPC {vpc_id}")
    return [s["SubnetId"] for s in subnets[:count]]


def _create_subnet_group(ctx: Any, subnet_ids: list[str]) -> str:
    ec = ctx.client("elasticache")
    name = ctx.unique_name("sim2real-ec-subnetgrp-")
    ec.create_cache_subnet_group(
        CacheSubnetGroupName=name,
        CacheSubnetGroupDescription="sim2real behavioral",
        SubnetIds=subnet_ids,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ec.delete_cache_subnet_group(CacheSubnetGroupName=name))
    return name


def _wait_rg_available(ctx: Any, rg_id: str, timeout_s: float = 900.0) -> dict:
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


def _delete_replication_group(ctx: Any, rg_id: str) -> None:
    """Delete rg_id and wait until it is gone; a group still creating is retried."""
    ec = ctx.client("elasticache")
    deadline = time.monotonic() + 900
    while True:
        try:
            ec.delete_replication_group(ReplicationGroupId=rg_id)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ReplicationGroupNotFoundFault":
                return
            if code != "InvalidReplicationGroupState" or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    while time.monotonic() < deadline:
        try:
            ec.describe_replication_groups(ReplicationGroupId=rg_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ReplicationGroupNotFoundFault":
                return
            raise
        time.sleep(2)
    raise AssertionError(f"replication group {rg_id} was not deleted within 900 s")


def _error_code(fn: Any) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected success raises, so a
    target that accepts input AWS refuses fails loudly rather than as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
