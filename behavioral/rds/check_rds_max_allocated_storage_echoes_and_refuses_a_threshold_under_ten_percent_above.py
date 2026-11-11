"""rds-max-allocated-storage-echoes-and-refuses-a-threshold-under-ten-percent-above."""
from __future__ import annotations

import secrets
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rds-max-allocated-storage-echoes-and-refuses-a-threshold-under-ten-percent-above"
GROUP = "server-side"
SERVICES = ["rds"]

_ALLOCATED_STORAGE_GIB = 20
#: Less than 10% above the allocated storage: below the documented floor for the threshold.
_TOO_LOW_MAX_GIB = 21
_MAX_ALLOCATED_STORAGE_GIB = 40
_TAGS = [{"Key": "sim2real", "Value": "true"}]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A maximum storage threshold less than 10% above the allocated storage is refused, and one
    set by ModifyDBInstance on an available postgres instance is echoed as MaxAllocatedStorage
    with AllocatedStorage unchanged: the bound storage autoscaling grows within.

    Reference: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_PIOPS.Autoscaling.html
    """
    rds = ctx.client("rds")
    net = ctx.network()
    subnet_group = _create_subnet_group(ctx, rds, net.subnet_ids)
    password = "S2r" + secrets.token_hex(8)
    common = {
        "DBInstanceClass": "db.t3.micro", "Engine": "postgres", "MasterUsername": "s2rtest",
        "MasterUserPassword": password, "AllocatedStorage": _ALLOCATED_STORAGE_GIB,
        "StorageType": "gp2", "DBName": "sim2real", "PubliclyAccessible": False,
        "DBSubnetGroupName": subnet_group, "Tags": _TAGS,
    }

    # ---- The threshold floor: CreateDBInstance refuses a maximum under 110% of the allocation.
    refused_id = ctx.unique_name("sim2real-rds-maxlow-")
    ctx.on_cleanup(lambda: _delete_instance(rds, refused_id))
    try:
        rds.create_db_instance(DBInstanceIdentifier=refused_id,
                               MaxAllocatedStorage=_TOO_LOW_MAX_GIB, **common)
    except ClientError as exc:
        error = exc.response["Error"]
    else:
        raise AssertionError(
            f"CreateDBInstance accepted MaxAllocatedStorage={_TOO_LOW_MAX_GIB} with "
            f"AllocatedStorage={_ALLOCATED_STORAGE_GIB}; the threshold must be at least 10% more")
    assert error.get("Code") == "InvalidParameterCombination", (
        f"the too-low threshold was refused with {error!r}, expected InvalidParameterCombination")
    want = "The maximum allocated storage must be increased by at least 10 percent."
    assert error.get("Message") == want, (
        f"the refusal message is {error.get('Message')!r}, expected {want!r}")
    missing = _describe(rds, refused_id)
    assert missing is None, f"the refused CreateDBInstance left an instance: {missing!r}"

    # ---- The echo: a threshold set on an available instance reads back exactly.
    instance_id = ctx.unique_name("sim2real-rds-maxok-")
    rds.create_db_instance(DBInstanceIdentifier=instance_id, **common)
    ctx.on_cleanup(lambda: _delete_instance(rds, instance_id))
    instance = _wait_for_status(rds, instance_id, "available", timeout_s=1500)
    assert instance["AllocatedStorage"] == _ALLOCATED_STORAGE_GIB, (
        f"the new instance reports AllocatedStorage {instance['AllocatedStorage']!r}, expected "
        f"{_ALLOCATED_STORAGE_GIB}")
    assert "MaxAllocatedStorage" not in instance, (
        f"an instance created without a threshold reports MaxAllocatedStorage "
        f"{instance.get('MaxAllocatedStorage')!r}; storage autoscaling is off until one is set")
    modified = rds.modify_db_instance(DBInstanceIdentifier=instance_id,
                                      MaxAllocatedStorage=_MAX_ALLOCATED_STORAGE_GIB,
                                      ApplyImmediately=True)["DBInstance"]
    assert modified["MaxAllocatedStorage"] == _MAX_ALLOCATED_STORAGE_GIB, (
        f"ModifyDBInstance answered MaxAllocatedStorage {modified.get('MaxAllocatedStorage')!r}, "
        f"expected {_MAX_ALLOCATED_STORAGE_GIB}")
    instance = _wait_for_status(rds, instance_id, "available", timeout_s=900)
    assert instance["MaxAllocatedStorage"] == _MAX_ALLOCATED_STORAGE_GIB, (
        f"DescribeDBInstances reports MaxAllocatedStorage {instance.get('MaxAllocatedStorage')!r} "
        f"after ModifyDBInstance, expected {_MAX_ALLOCATED_STORAGE_GIB}")
    assert instance["AllocatedStorage"] == _ALLOCATED_STORAGE_GIB, (
        f"setting the threshold changed AllocatedStorage to {instance['AllocatedStorage']!r}")

    # Delete in the body: an instance outlives the cleanup bound, and its subnet group with it.
    rds.delete_db_instance(DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True)
    rds.get_waiter("db_instance_deleted").wait(
        DBInstanceIdentifier=instance_id, WaiterConfig={"Delay": 2, "MaxAttempts": 600})


def _describe(rds: Any, instance_id: str) -> dict | None:
    try:
        return rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "DBInstanceNotFound":
            return None
        raise


def _delete_instance(rds: Any, instance_id: str) -> None:
    """Delete the instance; one already gone or already being deleted is done."""
    found = _describe(rds, instance_id)
    if found is None or found["DBInstanceStatus"] == "deleting":
        return
    try:
        rds.delete_db_instance(DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBInstanceNotFound":
            raise


def _create_subnet_group(ctx: Any, rds: Any, subnet_ids: list[str]) -> str:
    """A DB subnet group over the run network's subnets, deleted after the instance."""
    name = ctx.unique_name("sim2real-rds-maxsng-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real rds storage threshold test",
        SubnetIds=subnet_ids,
        Tags=_TAGS,
    )
    ctx.on_cleanup(lambda: _delete_when_released(
        lambda: rds.delete_db_subnet_group(DBSubnetGroupName=name),
        in_use="InvalidDBSubnetGroupStateFault", not_found="DBSubnetGroupNotFoundFault",
    ))
    return name


def _delete_when_released(delete: Callable[[], Any], *, in_use: str, not_found: str) -> None:
    """Retry ``delete`` while a deleted instance still holds the resource, for a bounded time."""
    deadline = time.monotonic() + 50.0
    while True:
        try:
            delete()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == not_found:
                return
            if code != in_use or time.monotonic() >= deadline:
                raise
        time.sleep(5.0)


def _wait_for_status(rds: Any, instance_id: str, status: str, *, timeout_s: float) -> dict:
    deadline = time.monotonic() + timeout_s
    while True:
        instance = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
        if instance["DBInstanceStatus"] == status:
            return instance
        if time.monotonic() >= deadline:
            raise AssertionError(f"instance {instance_id} never reached {status!r} within "
                                 f"{timeout_s}s (last: {instance['DBInstanceStatus']!r})")
        time.sleep(5)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
