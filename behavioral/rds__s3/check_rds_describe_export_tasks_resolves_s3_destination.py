"""rds-describe-export-tasks-resolves-s3-destination."""

from __future__ import annotations

import json
import secrets
import time

from botocore.exceptions import ClientError

import botocore.exceptions

from behavioral_harness import tags

CHECK = "rds-describe-export-tasks-resolves-s3-destination"
GROUP = "arn-resolution"
SERVICES = ["rds", "s3"]

EXPORT_PRINCIPAL = "export.rds.amazonaws.com"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeExportTasks resolves and echoes back the exact S3 bucket name,
    S3 prefix and source snapshot ARN that were supplied at StartExportTask
    time -- not a normalized/lowercased/truncated variant."""
    rds = ctx.client("rds")

    bucket = _create_bucket(ctx)
    key_arn = _create_kms_key(ctx)
    snapshot_arn = _provision_snapshot(ctx)
    role_arn = _create_export_role(ctx, EXPORT_PRINCIPAL, bucket, key_arn)

    task_id = ctx.unique_name("sim2real-export-")
    prefix = "arn-resolution/nested/prefix"
    _start_export_task_with_retry(
        rds,
        ExportTaskIdentifier=task_id,
        SourceArn=snapshot_arn,
        S3BucketName=bucket,
        IamRoleArn=role_arn,
        KmsKeyId=key_arn,
        S3Prefix=prefix,
    )
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: rds.cancel_export_task(ExportTaskIdentifier=task_id)
        )
    )

    task = rds.describe_export_tasks(ExportTaskIdentifier=task_id)["ExportTasks"][0]
    assert task["ExportTaskIdentifier"] == task_id, (
        f"ExportTaskIdentifier mismatch: {task['ExportTaskIdentifier']!r} != {task_id!r}"
    )
    assert task["S3Bucket"] == bucket, (
        f"S3Bucket mismatch: {task['S3Bucket']!r} != {bucket!r}"
    )
    assert task["S3Prefix"] == prefix, (
        f"S3Prefix mismatch: {task['S3Prefix']!r} != {prefix!r}"
    )
    assert task["SourceArn"] == snapshot_arn, (
        f"SourceArn mismatch: {task['SourceArn']!r} != {snapshot_arn!r}"
    )
    assert task["IamRoleArn"] == role_arn, (
        f"IamRoleArn mismatch: {task['IamRoleArn']!r} != {role_arn!r}"
    )


def _poll_until(probe, predicate, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _best_effort(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "DBInstanceNotFound",
            "DBSnapshotNotFound",
            "ExportTaskNotFound",
            "NoSuchBucket",
            "NoSuchEntity",
            "NotFoundException",
        ):
            raise


def _random_password() -> str:
    return "Aa1" + secrets.token_urlsafe(14)


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-rdss3-")
    if (
        ctx.region == "us-east-1"
    ):  # CreateBucket rejects an explicit LocationConstraint here
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(
        Bucket=name,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": "rds-s3-behavioral"}]},
    )
    ctx.on_cleanup(lambda: _best_effort(lambda: _empty_and_delete_bucket(ctx, name)))
    return name


def _empty_and_delete_bucket(ctx, name: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=name):
        keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if keys:
            failed = s3.delete_objects(Bucket=name, Delete={"Objects": keys}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=name)


def _create_kms_key(ctx) -> str:
    kms = ctx.client("kms")
    key = kms.create_key(
        Description="sim2real rds-s3 export test key",
        Tags=[{"TagKey": "sim2real", "TagValue": "rds-s3-behavioral"}],
    )["KeyMetadata"]
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: kms.schedule_key_deletion(KeyId=key["KeyId"], PendingWindowInDays=7)
        )
    )
    return key["Arn"]


def _create_export_role(ctx, principal: str, bucket_name: str, key_arn: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-rdss3-role-")
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
    ctx.on_cleanup(lambda: _best_effort(lambda: iam.delete_role(RoleName=role_name)))

    statements = [
        {
            "Sid": "S3Export",
            "Effect": "Allow",
            "Action": [
                "s3:PutObject*",
                "s3:ListBucket",
                "s3:GetObject*",
                "s3:DeleteObject*",
                "s3:GetBucketLocation",
            ],
            "Resource": [
                f"arn:aws:s3:::{bucket_name}",
                f"arn:aws:s3:::{bucket_name}/*",
            ],
        },
        {
            "Sid": "KmsExport",
            "Effect": "Allow",
            "Action": ["kms:CreateGrant", "kms:DescribeKey"],
            "Resource": key_arn,
        },
    ]
    policy_name = f"{role_name}-policy"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        )
    )
    return role["Arn"]


def _start_export_task_with_retry(rds, *, timeout_s=150.0, interval_s=15.0, **kwargs):
    # A freshly created IAM role/KMS grant can take a short time to propagate; see
    # https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_general.html#troubleshoot_general_eventual-consistency
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return rds.start_export_task(**kwargs)
        except botocore.exceptions.ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("IamRoleMissingPermissions", "KMSKeyNotAccessibleFault"):
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise last_exc


def _provision_snapshot(ctx) -> str:
    """Create a minimal RDS instance and a manual snapshot of it, returning the
    snapshot ARN. This check only needs a valid SourceArn -- it never waits for
    the export task itself to complete, so the instance doesn't need seeded
    data or network reachability."""
    rds = ctx.client("rds")
    db_id = ctx.unique_name("sim2real-rdss3-db-")
    password = _random_password()
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=db_id,
        Engine="postgres",
        DBInstanceClass="db.t3.micro",
        AllocatedStorage=20,
        MasterUsername="dbadmin",
        MasterUserPassword=password,
        BackupRetentionPeriod=0,
        Tags=[{"Key": "sim2real", "Value": "rds-s3-behavioral"}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: rds.delete_db_instance(
                DBInstanceIdentifier=db_id, SkipFinalSnapshot=True
            )
        )
    )
    _poll_until(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0][
            "DBInstanceStatus"
        ],
        lambda status: status == "available",
        timeout_s=1200,
        interval_s=20,
    )

    snap_id = ctx.unique_name("sim2real-rdss3-snap-")
    rds.create_db_snapshot(
        DBSnapshotIdentifier=snap_id,
        DBInstanceIdentifier=db_id,
        Tags=[{"Key": "sim2real", "Value": "rds-s3-behavioral"}],
    )
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: rds.delete_db_snapshot(DBSnapshotIdentifier=snap_id)
        )
    )
    snap = _poll_until(
        lambda: rds.describe_db_snapshots(DBSnapshotIdentifier=snap_id)["DBSnapshots"][
            0
        ],
        lambda s: s["Status"] == "available",
        timeout_s=900,
        interval_s=15,
    )
    return snap["DBSnapshotArn"]


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
