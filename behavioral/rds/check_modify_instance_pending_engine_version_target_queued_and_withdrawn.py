"""modify-instance-pending-engine-version-target-queued-and-withdrawn."""
from __future__ import annotations

import secrets
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-instance-pending-engine-version-target-queued-and-withdrawn"
GROUP = "engine-version"
SERVICES = ["rds"]

_BASE_VERSION = "13.23"
_MAJOR_TARGET = "14.20"
_MINOR_TARGET = "13.23-rds.20260224"
_TAGS = [{"Key": "sim2real", "Value": "true"}]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A major engine-version target with AllowMajorVersionUpgrade queues in
    PendingModifiedValues.EngineVersion while the live version stays current; resubmitting the
    current version withdraws it, and a minor target queues the same way with no such flag.

    Reference: https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_ModifyDBInstance.html
    """
    rds = ctx.client("rds")
    subnet_group = _create_subnet_group(ctx, rds)
    password = "S2r" + secrets.token_hex(8)
    instance_id = ctx.unique_name("sim2real-rds-everpend-")
    rds.create_db_instance(
        DBInstanceIdentifier=instance_id, DBInstanceClass="db.t3.micro", Engine="postgres",
        EngineVersion=_BASE_VERSION, MasterUsername="sim2realadmin",
        MasterUserPassword=password, AllocatedStorage=20, StorageType="gp2",
        PubliclyAccessible=False, DBSubnetGroupName=subnet_group, Tags=_TAGS,
    )
    ctx.on_cleanup(lambda: _delete_instance_and_wait(rds, instance_id))
    instance = _wait_for_status(rds, instance_id, "available", timeout_s=1500)
    assert instance["EngineVersion"] == _BASE_VERSION, (
        f"the new instance reports EngineVersion {instance['EngineVersion']!r}, expected "
        f"{_BASE_VERSION!r}")

    # ---- A major jump with the flag is accepted and queued; the live version does not move.
    queued = rds.modify_db_instance(
        DBInstanceIdentifier=instance_id, EngineVersion=_MAJOR_TARGET,
        AllowMajorVersionUpgrade=True, ApplyImmediately=False,
    )["DBInstance"]
    assert queued.get("PendingModifiedValues", {}).get("EngineVersion") == _MAJOR_TARGET, (
        f"ModifyDBInstance answered PendingModifiedValues "
        f"{queued.get('PendingModifiedValues')!r}, expected EngineVersion {_MAJOR_TARGET!r}")
    assert queued["EngineVersion"] == _BASE_VERSION, (
        f"the modify response reports live EngineVersion {queued['EngineVersion']!r} while "
        f"the major target is only pending; expected it to stay {_BASE_VERSION!r}")
    instance = _describe(rds, instance_id)
    assert instance.get("PendingModifiedValues", {}).get("EngineVersion") == _MAJOR_TARGET, (
        f"an independent DescribeDBInstances reports PendingModifiedValues "
        f"{instance.get('PendingModifiedValues')!r}, expected EngineVersion {_MAJOR_TARGET!r}")
    assert instance["EngineVersion"] == _BASE_VERSION, (
        f"an independent DescribeDBInstances reports live EngineVersion "
        f"{instance['EngineVersion']!r}, expected it to stay {_BASE_VERSION!r}")

    # ---- Resubmitting the current version withdraws the pending major target.
    withdrawn = rds.modify_db_instance(
        DBInstanceIdentifier=instance_id, EngineVersion=_BASE_VERSION, ApplyImmediately=False,
    )["DBInstance"]
    assert "EngineVersion" not in withdrawn.get("PendingModifiedValues", {}), (
        f"resubmitting the current version {_BASE_VERSION!r} should withdraw the pending major "
        f"target, but the modify response still carries PendingModifiedValues "
        f"{withdrawn.get('PendingModifiedValues')!r}")
    assert withdrawn["EngineVersion"] == _BASE_VERSION, (
        f"after withdrawing the pending target the live EngineVersion reports "
        f"{withdrawn['EngineVersion']!r}, expected it to stay {_BASE_VERSION!r}")
    instance = _describe(rds, instance_id)
    assert "EngineVersion" not in instance.get("PendingModifiedValues", {}), (
        f"an independent DescribeDBInstances still carries a pending EngineVersion in "
        f"{instance.get('PendingModifiedValues')!r} after the withdrawal")
    assert instance["EngineVersion"] == _BASE_VERSION, (
        f"an independent DescribeDBInstances reports live EngineVersion "
        f"{instance['EngineVersion']!r} after the withdrawal, expected it to stay "
        f"{_BASE_VERSION!r}")

    # ---- A minor jump is accepted and queued with no AllowMajorVersionUpgrade at all.
    minor_queued = rds.modify_db_instance(
        DBInstanceIdentifier=instance_id, EngineVersion=_MINOR_TARGET, ApplyImmediately=False,
    )["DBInstance"]
    assert minor_queued.get("PendingModifiedValues", {}).get("EngineVersion") == _MINOR_TARGET, (
        f"ModifyDBInstance with no AllowMajorVersionUpgrade answered PendingModifiedValues "
        f"{minor_queued.get('PendingModifiedValues')!r} for the minor target {_MINOR_TARGET!r}")
    assert minor_queued["EngineVersion"] == _BASE_VERSION, (
        f"the minor-target modify response reports live EngineVersion "
        f"{minor_queued['EngineVersion']!r}, expected it to stay {_BASE_VERSION!r}")
    instance = _describe(rds, instance_id)
    assert instance.get("PendingModifiedValues", {}).get("EngineVersion") == _MINOR_TARGET, (
        f"an independent DescribeDBInstances reports PendingModifiedValues "
        f"{instance.get('PendingModifiedValues')!r}, expected the queued minor target "
        f"{_MINOR_TARGET!r}")
    assert instance["EngineVersion"] == _BASE_VERSION, (
        f"an independent DescribeDBInstances reports live EngineVersion "
        f"{instance['EngineVersion']!r} with the minor target still pending, expected it to "
        f"stay {_BASE_VERSION!r}")


def _describe(rds: Any, instance_id: str) -> dict:
    return rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]


def _wait_for_status(rds: Any, instance_id: str, status: str, *, timeout_s: float) -> dict:
    deadline = time.monotonic() + timeout_s
    while True:
        instance = _describe(rds, instance_id)
        if instance["DBInstanceStatus"] == status:
            return instance
        if time.monotonic() >= deadline:
            raise AssertionError(f"instance {instance_id} never reached {status!r} within "
                                 f"{timeout_s}s (last: {instance['DBInstanceStatus']!r})")
        time.sleep(5)


def _delete_instance_and_wait(rds: Any, instance_id: str, *, timeout_s: float = 1500.0) -> None:
    """Delete the instance and wait until it is gone, so a following subnet-group teardown
    does not race an instance still ``deleting``."""
    try:
        rds.delete_db_instance(DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "DBInstanceNotFound":
            return
        raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            rds.describe_db_instances(DBInstanceIdentifier=instance_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "DBInstanceNotFound":
                return
            raise
        time.sleep(10)
    raise AssertionError(f"instance {instance_id} was not deleted within {timeout_s}s")


def _create_subnet_group(ctx: Any, rds: Any) -> str:
    name = ctx.unique_name("sim2real-rds-everpend-sng-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real rds pending engine version test",
        SubnetIds=ctx.network().subnet_ids,
        Tags=_TAGS,
    )
    ctx.on_cleanup(_teardown(
        lambda: rds.delete_db_subnet_group(DBSubnetGroupName=name), "DBSubnetGroupNotFoundFault",
    ))
    return name


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
