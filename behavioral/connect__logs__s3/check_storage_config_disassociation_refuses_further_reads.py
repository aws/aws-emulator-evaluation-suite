"""storage-config-disassociation-refuses-further-reads."""

from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "storage-config-disassociation-refuses-further-reads"
GROUP = "storage-config-lifecycle"
SERVICES = ["connect", "logs", "s3"]

#: DescribeInstanceStorageConfig's refusal for an AssociationId it does not recognize, whether it
#: was never associated or was already disassociated, and the refusal UpdateInstanceStorageConfig
#: and DisassociateInstanceStorageConfig give for one.
_NOT_FOUND = ("ResourceNotFoundException", "Resource not found")
_STORAGE_CONFIG_NOT_FOUND = ("ResourceNotFoundException", "Storage Config not found")

_DELETE_TIMEOUT_S = 300.0
_CREATE_TIMEOUT_S = 300.0


def expect_error(fn, code: str, message: str) -> None:
    """Assert ``fn()`` is refused with exactly ``(code, message)``; raise on an unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        assert err.get("Code") == code, (
            f"expected {code!r}, got {err.get('Code')!r}: {err.get('Message')!r}"
        )
        assert err.get("Message") == message, f"expected message {message!r}, got {err.get('Message')!r}"
        return
    raise AssertionError(f"expected {code!r} ({message!r}), but the call succeeded: {result!r}")


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0,
                     budget_s: float = 180.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent.

    A Connect instance's log group can appear after the instance itself is already deleted, so a
    single delete is not enough to call it gone.
    """
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"log group {name!r} still present after {budget_s}s of deletes"
                )
            time.sleep(interval_s)


def _delete_instance_and_buckets(connect, s3, instance_id: str, buckets: list) -> None:
    """DeleteInstance (retried while the instance is still settling), then its own bucket(s).

    DeleteInstance takes the instance's own storage associations with it; the bucket is this run's
    and is removed once the instance it was never required to outlive is gone.
    """
    deadline = time.monotonic() + _DELETE_TIMEOUT_S
    while True:
        try:
            connect.delete_instance(InstanceId=instance_id)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                break
            if code != "InvalidRequestException" or time.monotonic() > deadline:
                raise
            time.sleep(3)
    while True:
        try:
            connect.describe_instance(InstanceId=instance_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                break
            raise
        if time.monotonic() > deadline:
            raise AssertionError(f"instance {instance_id!r} still describable after DeleteInstance")
        time.sleep(3)
    for bucket in buckets:
        try:
            s3.delete_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """Disassociating an instance's S3 storage config refuses a later Describe on that
    AssociationId exactly like one never associated, while the instance stays live; an update or
    a disassociation naming an unknown AssociationId is refused "Storage Config not found".
    """
    connect = ctx.client("connect")
    s3 = ctx.client("s3")
    logs = ctx.client("logs")
    alias = ctx.unique_name("sim2real-connio-").lower()

    # Registered before create_instance so LIFO reaps the log group last, after DeleteInstance.
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/connect/{alias}"))

    instance_id = connect.create_instance(
        IdentityManagementType="CONNECT_MANAGED",
        InstanceAlias=alias,
        InboundCallsEnabled=True,
        OutboundCallsEnabled=True,
    )["Id"]
    buckets: list = []
    ctx.on_cleanup(lambda: _delete_instance_and_buckets(connect, s3, instance_id, buckets))

    deadline = time.monotonic() + _CREATE_TIMEOUT_S
    while True:
        status = connect.describe_instance(InstanceId=instance_id)["Instance"]["InstanceStatus"]
        if status != "CREATION_IN_PROGRESS":
            break
        assert time.monotonic() < deadline, f"instance {instance_id!r} still {status!r}"
        time.sleep(5)
    assert status == "ACTIVE", f"instance {instance_id!r} ended {status!r}, not ACTIVE"

    bucket = ctx.unique_name("sim2real-connio-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    buckets.append(bucket)

    prefix = "recordings"
    association_id = connect.associate_instance_storage_config(
        InstanceId=instance_id,
        ResourceType="CALL_RECORDINGS",
        StorageConfig={"StorageType": "S3", "S3Config": {"BucketName": bucket, "BucketPrefix": prefix}},
    )["AssociationId"]
    want = {"AssociationId": association_id, "StorageType": "S3",
            "S3Config": {"BucketName": bucket, "BucketPrefix": prefix}}

    pages = connect.get_paginator("list_instance_storage_configs").paginate(
        InstanceId=instance_id, ResourceType="CALL_RECORDINGS"
    )
    configs = [c for page in pages for c in page["StorageConfigs"]]
    assert configs == [want], f"ListInstanceStorageConfigs returned {configs!r}, expected [{want!r}]"

    described = connect.describe_instance_storage_config(
        InstanceId=instance_id, AssociationId=association_id, ResourceType="CALL_RECORDINGS"
    )["StorageConfig"]
    assert described == want, f"DescribeInstanceStorageConfig returned {described!r}, expected {want!r}"

    new_prefix = "recordings-updated"
    connect.update_instance_storage_config(
        InstanceId=instance_id,
        AssociationId=association_id,
        ResourceType="CALL_RECORDINGS",
        StorageConfig={"StorageType": "S3", "S3Config": {"BucketName": bucket, "BucketPrefix": new_prefix}},
    )
    updated = connect.describe_instance_storage_config(
        InstanceId=instance_id, AssociationId=association_id, ResourceType="CALL_RECORDINGS"
    )["StorageConfig"]
    assert updated["S3Config"]["BucketPrefix"] == new_prefix, (
        f"after UpdateInstanceStorageConfig, DescribeInstanceStorageConfig still reports prefix "
        f"{updated['S3Config']['BucketPrefix']!r}, expected {new_prefix!r}"
    )

    connect.disassociate_instance_storage_config(
        InstanceId=instance_id, AssociationId=association_id, ResourceType="CALL_RECORDINGS"
    )
    expect_error(
        lambda: connect.describe_instance_storage_config(
            InstanceId=instance_id, AssociationId=association_id, ResourceType="CALL_RECORDINGS"
        ),
        *_NOT_FOUND,
    )

    # Positive control: disassociating the storage config does not touch the instance itself.
    live = connect.describe_instance(InstanceId=instance_id)["Instance"]
    assert live["InstanceStatus"] == "ACTIVE", (
        f"instance {instance_id!r} is {live['InstanceStatus']!r} after disassociation, expected ACTIVE"
    )

    unknown_association_id = str(uuid.uuid4())
    expect_error(
        lambda: connect.describe_instance_storage_config(
            InstanceId=instance_id, AssociationId=unknown_association_id, ResourceType="CALL_RECORDINGS"
        ),
        *_NOT_FOUND,
    )
    expect_error(
        lambda: connect.update_instance_storage_config(
            InstanceId=instance_id,
            AssociationId=unknown_association_id,
            ResourceType="CALL_RECORDINGS",
            StorageConfig={"StorageType": "S3", "S3Config": {"BucketName": bucket, "BucketPrefix": prefix}},
        ),
        *_STORAGE_CONFIG_NOT_FOUND,
    )
    expect_error(
        lambda: connect.disassociate_instance_storage_config(
            InstanceId=instance_id, AssociationId=unknown_association_id, ResourceType="CALL_RECORDINGS"
        ),
        *_STORAGE_CONFIG_NOT_FOUND,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
