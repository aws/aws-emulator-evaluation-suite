"""rds-snapshot-export-task-missing-s3-put-permission-negative."""

from __future__ import annotations

import json
import secrets
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rds-snapshot-export-task-missing-s3-put-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["rds", "s3"]


@tags("axis:rejection", "cap:c4", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx: Any) -> None:
    """StartExportTask rejects at once a role that trusts export.rds.amazonaws.com but lacks s3:PutObject on
    the bucket, creating no task and writing nothing; the identical call with a role that has
    s3:PutObject is accepted and its task leaves STARTING without failing."""
    rds = ctx.client("rds")
    s3 = ctx.client("s3")

    bucket = _create_export_bucket(ctx)
    kms_key_id, _ = _create_kms_key(ctx)
    snapshot_arn = _create_snapshot_source(ctx)

    broken_role_arn = _create_export_role(
        ctx, allow_s3_put=False, trust_export_service=True, bucket_name=bucket
    )
    fail_export_id = ctx.unique_name("sim2real-export-fail-").lower()

    code, message = _error_code_with_retry(
        lambda: rds.start_export_task(
            ExportTaskIdentifier=fail_export_id,
            SourceArn=snapshot_arn,
            S3BucketName=bucket,
            IamRoleArn=broken_role_arn,
            KmsKeyId=kms_key_id,
            S3Prefix="rds-export-nowrite",
        ),
        retryable_codes=("KMSKeyNotAccessibleFault",),
    )
    assert code == "IamRoleMissingPermissions", (
        f"expected IamRoleMissingPermissions for a role without s3:PutObject, got {code!r}"
    )
    assert message == (
        f"The IAM role {broken_role_arn} isn't authorized to call s3:PutObject on the S3 "
        f"bucket {bucket}."
    ), message

    # The task must never have been created, so no export task record and no
    # S3 objects should exist for this export identifier.
    tasks = _list_export_tasks_quietly(rds, fail_export_id)
    assert tasks == [], (
        f"export task {fail_export_id} unexpectedly exists after rejection"
    )
    listing = s3.list_objects_v2(Bucket=bucket, Prefix="rds-export-nowrite")
    keys = [o["Key"] for o in listing.get("Contents", []) if fail_export_id in o["Key"]]
    assert keys == [], (
        f"S3 objects were written despite the rejected export task: {keys!r}"
    )

    # Positive control: the same bucket/snapshot/kms key with a role that DOES
    # have s3:PutObject is accepted (no exception, task not immediately FAILED).
    good_role_arn = _create_export_role(
        ctx, allow_s3_put=True, trust_export_service=True, bucket_name=bucket
    )
    ok_export_id = ctx.unique_name("sim2real-export-ok-").lower()
    _start_export_task_with_retry(
        rds,
        ExportTaskIdentifier=ok_export_id,
        SourceArn=snapshot_arn,
        S3BucketName=bucket,
        IamRoleArn=good_role_arn,
        KmsKeyId=kms_key_id,
        S3Prefix="rds-export-control",
    )
    ctx.on_cleanup(lambda: _cancel_export_quietly(ctx, ok_export_id))

    # Independent read at a different operation than the one that mutated: the control
    # task must leave STARTING and must not land in FAILED.
    observed = _poll_until(
        lambda: rds.describe_export_tasks(ExportTaskIdentifier=ok_export_id)[
            "ExportTasks"
        ][0],
        lambda t: t["Status"] != "STARTING",
        timeout_s=900.0,
        interval_s=15.0,
        description=f"export task {ok_export_id} to leave STARTING",
    )
    assert observed["Status"] != "FAILED", (
        f"control export task with a correctly-permissioned role failed: {observed}"
    )


def _error_code_with_retry(
    fn: Any,
    *,
    retryable_codes: tuple[str, ...],
    timeout_s: float = 90.0,
    interval_s: float = 5.0,
) -> tuple[str, str]:
    """Return the (code, message) of the ClientError fn() raises, retrying while the code is
    one of *retryable_codes* -- IAM/KMS grants attached moments earlier can transiently surface
    as e.g. KMSKeyNotAccessibleFault before they propagate, which would otherwise mask the real,
    persistent rejection code this check asserts on. An unexpected success raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in retryable_codes and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            return code, err.response["Error"]["Message"]
        raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _start_export_task_with_retry(
    rds: Any, *, timeout_s: float = 90.0, **kwargs: Any
) -> dict:
    """StartExportTask with a correctly-permissioned role can still transiently surface
    IamRoleMissingPermissions/AccessDenied/KMSKeyNotAccessibleFault while the IAM policy and
    KMS grant attached moments earlier propagate; retry on those specific codes only, up to a
    deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return rds.start_export_task(**kwargs)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if (
                code
                in (
                    "IamRoleMissingPermissions",
                    "AccessDenied",
                    "KMSKeyNotAccessibleFault",
                )
                and time.monotonic() < deadline
            ):
                time.sleep(5)
                continue
            raise


def _poll_until(
    probe: Any, predicate: Any, *, timeout_s: float, interval_s: float, description: str
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"timed out waiting for {description}; last observed: {last!r}"
    )


def _list_export_tasks_quietly(rds: Any, export_id: str) -> list[Any]:
    try:
        return rds.describe_export_tasks(ExportTaskIdentifier=export_id).get(
            "ExportTasks", []
        )
    except ClientError:
        return []


def _password() -> str:
    raw = secrets.token_urlsafe(24).replace("-", "x").replace("_", "y")
    return (raw + "Aa1bB2")[:32]


def _create_export_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-rds-export-")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        # CreateBucket rejects an explicit LocationConstraint for us-east-1 itself.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=name,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": "rds-s3-behavioral"}]},
    )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx: Any, name: str) -> None:
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=name):
            objs = page.get("Contents", [])
            if objs:
                failed = s3.delete_objects(
                    Bucket=name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
                ).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_kms_key(ctx: Any) -> tuple[str, str]:
    kms = ctx.client("kms")
    key = kms.create_key(
        Description="sim2real rds export test key",
        Tags=[{"TagKey": "sim2real", "TagValue": "rds-s3-behavioral"}],
    )["KeyMetadata"]
    ctx.on_cleanup(
        lambda: kms.schedule_key_deletion(KeyId=key["KeyId"], PendingWindowInDays=7)
    )
    return key["KeyId"], key["Arn"]


def _create_export_role(
    ctx: Any,
    *,
    allow_s3_put: bool,
    trust_export_service: bool,
    bucket_name: str | None,
) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-rds-export-role-")
    principal = (
        "export.rds.amazonaws.com" if trust_export_service else "ec2.amazonaws.com"
    )
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": principal},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "rds-s3-behavioral"}],
    )["Role"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))

    s3_actions = ["s3:ListBucket", "s3:GetObject*", "s3:GetBucketLocation"]
    if allow_s3_put:
        s3_actions += ["s3:PutObject*", "s3:DeleteObject*"]
    resources: Any = "*"
    if bucket_name:
        resources = [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"]
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "S3Export",
                "Effect": "Allow",
                "Action": s3_actions,
                "Resource": resources,
            },
            {
                "Sid": "KmsExport",
                "Effect": "Allow",
                "Action": ["kms:CreateGrant", "kms:DescribeKey"],
                "Resource": "*",
            },
        ],
    }
    policy_name = f"{role_name}-policy"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(policy_doc),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    )
    return role["Arn"]


def _delete_role(ctx: Any, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        for p in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=p)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_snapshot_source(ctx: Any) -> str:
    rds = ctx.client("rds")
    instance_id = ctx.unique_name("sim2real-rds-export-src-").lower()
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=instance_id,
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername="sim2realadmin",
        MasterUserPassword=_password(),
        AllocatedStorage=20,
        BackupRetentionPeriod=0,
        PubliclyAccessible=False,
        Tags=[{"Key": "sim2real", "Value": "rds-s3-behavioral"}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_instance(ctx, instance_id))
    rds.get_waiter("db_instance_available").wait(
        DBInstanceIdentifier=instance_id, WaiterConfig={"Delay": 2, "MaxAttempts": 1200}
    )

    snapshot_id = ctx.unique_name("sim2real-rds-export-snap-").lower()
    rds.create_db_snapshot(
        DBInstanceIdentifier=instance_id,
        DBSnapshotIdentifier=snapshot_id,
        Tags=[{"Key": "sim2real", "Value": "rds-s3-behavioral"}],
    )
    ctx.on_cleanup(lambda: _delete_snapshot(ctx, snapshot_id))
    rds.get_waiter("db_snapshot_available").wait(
        DBSnapshotIdentifier=snapshot_id, WaiterConfig={"Delay": 2, "MaxAttempts": 900}
    )
    desc = rds.describe_db_snapshots(DBSnapshotIdentifier=snapshot_id)["DBSnapshots"][0]
    return desc["DBSnapshotArn"]


def _delete_instance(ctx: Any, instance_id: str) -> None:
    rds = ctx.client("rds")
    try:
        rds.delete_db_instance(DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBInstanceNotFound":
            raise


def _delete_snapshot(ctx: Any, snapshot_id: str) -> None:
    rds = ctx.client("rds")
    try:
        rds.delete_db_snapshot(DBSnapshotIdentifier=snapshot_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBSnapshotNotFound":
            raise


def _cancel_export_quietly(ctx: Any, export_id: str) -> None:
    rds = ctx.client("rds")
    try:
        rds.cancel_export_task(ExportTaskIdentifier=export_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExportTaskNotFound":
            raise


def _network_db_subnet_group(ctx, client) -> str:
    """A DB subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-dbsg-")
    client.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda: _delete_when_released(
            lambda: client.delete_db_subnet_group(DBSubnetGroupName=name),
            ("InvalidDBSubnetGroupStateFault", "InvalidDBSubnetGroupState"),
            ("DBSubnetGroupNotFoundFault",),
        )
    )
    return name


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=1500.0, interval_s=15.0):
    """Delete a subnet group, retrying while a resource that is being deleted still uses it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in gone_codes:
                return
            if code not in busy_codes or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
