"""modify-instance-engine-version-downgrade-rejected."""
from __future__ import annotations

import secrets
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-instance-engine-version-downgrade-rejected"
GROUP = "engine-version"
SERVICES = ["rds"]

_BASE_VERSION = "14.20"
_DOWNGRADE_TARGET = "13.23"
_UPGRADE_TARGET = "15.15"
_TAGS = [{"Key": "sim2real", "Value": "true"}]
_DOWNGRADE_REFUSED = (
    "InvalidParameterCombination",
    f"Cannot upgrade postgres from {_BASE_VERSION} to {_DOWNGRADE_TARGET}",
)


def _expect_error(fn, code: str, message: str) -> None:
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
    else:
        raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")
    assert error.get("Code") == code, f"the call was refused with {error!r}, expected code {code!r}"
    assert error.get("Message") == message, (
        f"the call was refused with message {error.get('Message')!r}, expected {message!r}")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ModifyDBInstance refuses lowering EngineVersion to an earlier major version even with
    AllowMajorVersionUpgrade, leaving the live version and pending state unchanged, while a
    legal higher major target is still accepted and queued.

    Reference: https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_ModifyDBInstance.html
    """
    rds = ctx.client("rds")
    subnet_group = _create_subnet_group(ctx, rds)
    password = "S2r" + secrets.token_hex(8)
    instance_id = ctx.unique_name("sim2real-rds-everdown-")
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

    # ---- The downgrade: refused even with the major-version-upgrade flag.
    _expect_error(
        lambda: rds.modify_db_instance(
            DBInstanceIdentifier=instance_id, EngineVersion=_DOWNGRADE_TARGET,
            AllowMajorVersionUpgrade=True, ApplyImmediately=False,
        ),
        *_DOWNGRADE_REFUSED,
    )
    instance = _describe(rds, instance_id)
    assert instance["EngineVersion"] == _BASE_VERSION, (
        f"a refused downgrade must leave the live EngineVersion at {_BASE_VERSION!r}, got "
        f"{instance['EngineVersion']!r}")
    assert "EngineVersion" not in instance.get("PendingModifiedValues", {}), (
        f"a refused downgrade must leave no pending EngineVersion, got "
        f"{instance.get('PendingModifiedValues')!r}")

    # ---- Positive control: the legal neighbor, a higher major target, is still accepted.
    accepted = rds.modify_db_instance(
        DBInstanceIdentifier=instance_id, EngineVersion=_UPGRADE_TARGET,
        AllowMajorVersionUpgrade=True, ApplyImmediately=False,
    )["DBInstance"]
    assert accepted.get("PendingModifiedValues", {}).get("EngineVersion") == _UPGRADE_TARGET, (
        f"a legal major-version target was answered with PendingModifiedValues "
        f"{accepted.get('PendingModifiedValues')!r}, expected EngineVersion {_UPGRADE_TARGET!r}")
    assert accepted["EngineVersion"] == _BASE_VERSION, (
        f"the modify response reports live EngineVersion {accepted['EngineVersion']!r} while "
        f"the upgrade target is only pending; expected it to stay {_BASE_VERSION!r}")


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
    name = ctx.unique_name("sim2real-rds-everdown-sng-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real rds engine version downgrade test",
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
