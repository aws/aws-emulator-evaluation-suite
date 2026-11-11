"""rds-snapshot-export-task-wrong-bucket-arn-negative."""
from __future__ import annotations

import json
import secrets
import time
import uuid
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rds-snapshot-export-task-wrong-bucket-arn-negative"
GROUP = "permission-boundary"
SERVICES = ["rds", "s3"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx: Any) -> None:
    """StartExportTask to a bucket that does not exist is rejected with InvalidS3BucketFault and creates
    no task, while the same call to a real bucket starts a task that does not fail."""
    rds = ctx.client("rds")
    s3 = ctx.client("s3")

    real_bucket = _create_export_bucket(ctx)
    kms_key_id, _ = _create_kms_key(ctx)
    role_arn = _create_export_role(
        ctx, allow_s3_put=True, trust_export_service=True, bucket_name=real_bucket
    )
    snapshot_arn = _create_snapshot_source(ctx)

    # 24 hex chars keep the name inside S3's 63-character limit, so RDS judges a
    # well-formed name that does not exist rather than a malformed one.
    nonexistent_bucket = f"sim2real-rds-export-nonexistent-{uuid.uuid4().hex[:24]}"
    # Guard against an astronomically unlikely name collision.
    try:
        s3.head_bucket(Bucket=nonexistent_bucket)
        raise AssertionError("nonexistent_bucket unexpectedly already exists")
    except ClientError as err:
        code = err.response["Error"]["Code"]
        assert code == "404", f"expected a not-found code, got {code!r}"
        assert err.response["Error"]["Message"] == "Not Found", err.response["Error"]

    fail_export_id = ctx.unique_name("sim2real-export-badbucket-").lower()
    code, message = _error_code(
        lambda: _start_export_task(
            rds,
            ExportTaskIdentifier=fail_export_id,
            SourceArn=snapshot_arn,
            S3BucketName=nonexistent_bucket,
            IamRoleArn=role_arn,
            KmsKeyId=kms_key_id,
            S3Prefix="rds-export-badbucket",
        )
    )
    assert code == "InvalidS3BucketFault", (
        f"expected InvalidS3BucketFault for a non-existent S3 bucket, got {code!r}"
    )
    assert message == (
        f"The S3 bucket {nonexistent_bucket} isn't valid. Either it isn't located in the "
        f"current AWS Region or it doesn't exist."
    ), message

    tasks = _list_export_tasks_quietly(rds, fail_export_id)
    assert tasks == [], f"export task {fail_export_id} unexpectedly exists after rejection"

    # Positive control: same role/snapshot/kms key, but the bucket is real.
    ok_export_id = ctx.unique_name("sim2real-export-goodbucket-").lower()
    resp = _start_export_task(
        rds,
        ExportTaskIdentifier=ok_export_id,
        SourceArn=snapshot_arn,
        S3BucketName=real_bucket,
        IamRoleArn=role_arn,
        KmsKeyId=kms_key_id,
        S3Prefix="rds-export-goodbucket-control",
    )
    ctx.on_cleanup(lambda: _cancel_export_quietly(ctx, ok_export_id))
    assert resp["Status"] != "FAILED", f"control export task against a real bucket was rejected: {resp}"

    # Terminal read: an independent DescribeExportTasks call, not the mutating call's own
    # response, confirms the control export actually progresses against the real bucket.
    # A new export task can stay in STARTING for several minutes before it begins
    # extracting, even for a near-empty snapshot.
    described = _poll_until(
        lambda: rds.describe_export_tasks(ExportTaskIdentifier=ok_export_id)["ExportTasks"][0],
        lambda task: task["Status"] != "STARTING",
        timeout_s=1200,
        interval_s=15.0,
        description="control export task to leave the transient STARTING state",
    )
    assert described["Status"] not in ("FAILED", "CANCELED", "CANCELING"), (
        f"control export task against a real bucket failed via an independent read: {described}"
    )


def _error_code(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s, interval_s=10.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _start_export_task(rds: Any, **kwargs: Any):
    """StartExportTask synchronously checks that the IAM role's trust policy lets
    export.rds.amazonaws.com assume it; a role created moments ago may not have propagated
    yet, so retry that specific transient rejection instead of sleeping blind."""
    for attempt in range(8):
        try:
            return rds.start_export_task(**kwargs)
        except ClientError as err:
            if err.response["Error"]["Code"] == "InvalidParameterValueException" and attempt < 7:
                time.sleep(5)
                continue
            raise
    raise AssertionError("unreachable")


def _list_export_tasks_quietly(rds: Any, export_id: str) -> list[Any]:
    try:
        return rds.describe_export_tasks(ExportTaskIdentifier=export_id).get("ExportTasks", [])
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
        # us-east-1 is S3's API default: CreateBucket rejects an explicit LocationConstraint
        # for that region, so it is only ever omitted, never pinned to it.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
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
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
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
    principal = "export.rds.amazonaws.com" if trust_export_service else "ec2.amazonaws.com"
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": principal}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
            {"Sid": "S3Export", "Effect": "Allow", "Action": s3_actions, "Resource": resources},
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
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
