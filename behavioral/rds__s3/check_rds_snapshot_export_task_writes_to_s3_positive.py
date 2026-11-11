"""rds-snapshot-export-task-writes-to-s3-positive."""
from __future__ import annotations

import json
import secrets
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rds-snapshot-export-task-writes-to-s3-positive"
GROUP = "data-export"
SERVICES = ["rds", "s3"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """Once a StartExportTask with a correct role and KMS key reaches COMPLETE, the bucket holds objects
    naming the export under its key prefix, among them export_info_<id>.json (the snapshot has no user
    tables, so no Parquet data part is expected)."""
    rds = ctx.client("rds")
    s3 = ctx.client("s3")

    bucket = _create_export_bucket(ctx)
    kms_key_id, _ = _create_kms_key(ctx)
    role_arn = _create_export_role(
        ctx, allow_s3_put=True, trust_export_service=True, bucket_name=bucket
    )
    snapshot_arn = _create_snapshot_source(ctx)

    export_id = ctx.unique_name("sim2real-export-").lower()
    prefix = "rds-export"
    _start_export_task_with_retry(
        rds,
        ExportTaskIdentifier=export_id,
        SourceArn=snapshot_arn,
        S3BucketName=bucket,
        IamRoleArn=role_arn,
        KmsKeyId=kms_key_id,
        S3Prefix=prefix,
    )
    ctx.on_cleanup(lambda: _cancel_export_quietly(ctx, export_id))

    status = _poll_export_status(
        ctx, export_id, {"COMPLETE", "FAILED", "CANCELED"}, timeout_s=2700, interval_s=30
    )
    assert status == "COMPLETE", f"export task ended in status {status!r}, expected COMPLETE"

    listing = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
    keys = [o["Key"] for o in listing.get("Contents", [])]
    matching = [k for k in keys if export_id in k]
    assert matching, (
        f"export task {export_id} reported COMPLETE but no S3 objects reference it "
        f"under prefix {prefix!r} (bucket objects seen: {keys!r})"
    )
    assert any(k.endswith(f"export_info_{export_id}.json") for k in matching), (
        f"export task {export_id} reported COMPLETE but its export_info manifest "
        f"object was not found among the written S3 objects: {matching!r}"
    )


def _password() -> str:
    raw = secrets.token_urlsafe(24).replace("-", "x").replace("_", "y")
    return (raw + "Aa1bB2")[:32]


def _create_export_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-rds-export-")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
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
    key = kms.create_key(Description="sim2real rds export test key")["KeyMetadata"]
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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]
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
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_instance(ctx, instance_id))
    rds.get_waiter("db_instance_available").wait(
        DBInstanceIdentifier=instance_id, WaiterConfig={"Delay": 2, "MaxAttempts": 1200}
    )

    snapshot_id = ctx.unique_name("sim2real-rds-export-snap-").lower()
    rds.create_db_snapshot(DBInstanceIdentifier=instance_id, DBSnapshotIdentifier=snapshot_id)
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


def _start_export_task_with_retry(rds: Any, *, timeout_s: float = 150.0, interval_s: float = 15.0, **kwargs: Any) -> None:
    """A freshly created IAM role/KMS grant can take a short time to propagate;
    retry StartExportTask on the specific eventual-consistency error codes."""
    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            rds.start_export_task(**kwargs)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("IamRoleMissingPermissions", "InvalidS3BucketFault", "KMSKeyNotAccessibleFault"):
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    assert last_exc is not None, "retry loop exited without ever calling start_export_task"
    raise last_exc


def _poll_export_status(
    ctx: Any, export_id: str, terminal_statuses: set[str], timeout_s: float, interval_s: float
) -> str:
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    last = "UNKNOWN"
    while time.monotonic() < deadline:
        tasks = rds.describe_export_tasks(ExportTaskIdentifier=export_id)["ExportTasks"]
        if tasks:
            last = tasks[0]["Status"]
            if last in terminal_statuses:
                return last
        time.sleep(interval_s)
    raise AssertionError(
        f"export task {export_id} did not reach a terminal status within {timeout_s}s (last={last})"
    )


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
