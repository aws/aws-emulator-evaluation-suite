"""cli-rds-list-export-tasks-shows-s3-target."""
from __future__ import annotations

import json
import subprocess
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cli-rds-list-export-tasks-shows-s3-target"
GROUP = "data-export"
SERVICES = ["rds", "s3"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """`aws rds describe-export-tasks` reports the exact S3 bucket/prefix
    target that was configured on `aws rds start-export-task`, verified via
    the SDK rather than by parsing CLI stdout.
    """
    from fidelity_tests_runner import require_tools

    require_tools("aws")

    bucket = _create_bucket(ctx)
    role_arn = _create_export_role(ctx, bucket)
    db_id = _create_encrypted_mysql_instance(ctx)
    _wait_instance_available(ctx, db_id)
    snapshot_arn = _create_snapshot(ctx, db_id)

    rds = ctx.client("rds")
    kms_key_arn = _create_export_kms_key(ctx)
    task_id = ctx.unique_name("sim2real-rds-export-cli-")
    prefix = "cli-target-check"
    proc = subprocess.run(
        [
            "aws", "rds", "start-export-task",
            "--export-task-identifier", task_id,
            "--source-arn", snapshot_arn,
            "--s3-bucket-name", bucket,
            "--iam-role-arn", role_arn,
            "--kms-key-id", kms_key_arn,
            "--s3-prefix", prefix,
        ],
        env=ctx.subprocess_env(),
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, f"aws rds start-export-task failed: {proc.stderr}"
    ctx.on_cleanup(lambda: _cancel_export_task(rds, task_id))

    task = rds.describe_export_tasks(ExportTaskIdentifier=task_id)["ExportTasks"][0]
    assert task["S3Bucket"] == bucket, f"expected S3Bucket={bucket!r}, got {task['S3Bucket']!r}"
    assert task["S3Prefix"] == prefix, f"expected S3Prefix={prefix!r}, got {task['S3Prefix']!r}"
    assert task["SourceArn"] == snapshot_arn, (
        f"expected SourceArn={snapshot_arn!r}, got {task['SourceArn']!r}"
    )


_PASSWORD = "Sim2Real9!Export"


def _poll_until(probe, predicate, timeout_s=1800.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-rds-s3-")
    # us-east-1 is the one region S3 rejects an explicit LocationConstraint for; checks run in
    # us-west-2, so this branch is unreachable in practice but kept for a correct CreateBucket call.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "rds-s3-behavioral"}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))
    return name


def _empty_and_delete_bucket(s3, name) -> None:
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=name):
        for obj in page.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
    s3.delete_bucket(Bucket=name)


def _create_export_role(ctx, bucket_name: str) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-rds-export-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "export.rds.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "rds-s3-behavioral"}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:PutObject*",
                    "s3:GetObject*",
                    "s3:ListBucket",
                    "s3:DeleteObject*",
                    "s3:GetBucketLocation",
                ],
                "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
            }
        ],
    }
    pol_name = ctx.unique_name("sim2real-rds-export-policy-")
    iam.put_role_policy(RoleName=name, PolicyName=pol_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName=pol_name))
    return role["Arn"]


def _create_export_kms_key(ctx) -> str:
    kms = ctx.client("kms")
    key = kms.create_key(
        Description=ctx.unique_name("sim2real-rds-export-kms-"),
        KeyUsage="ENCRYPT_DECRYPT",
        Tags=[{"TagKey": "sim2real", "TagValue": "rds-s3-behavioral"}],
    )["KeyMetadata"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key["KeyId"], PendingWindowInDays=7))
    return key["Arn"]


def _create_encrypted_mysql_instance(ctx) -> str:
    rds = ctx.client("rds")
    db_id = ctx.unique_name("sim2real-rds-src-")
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=db_id,
        Engine="mysql",
        DBInstanceClass="db.t3.micro",
        AllocatedStorage=20,
        MasterUsername="sim2root",
        MasterUserPassword=_PASSWORD,
        StorageEncrypted=True,
        BackupRetentionPeriod=1,
        PubliclyAccessible=False,
        Tags=[{"Key": "sim2real", "Value": "rds-s3-behavioral"}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: rds.delete_db_instance(DBInstanceIdentifier=db_id, SkipFinalSnapshot=True))
    return db_id


def _wait_instance_available(ctx, db_id: str) -> dict[str, Any]:
    rds = ctx.client("rds")

    def probe():
        return rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0]

    return _poll_until(probe, lambda i: i["DBInstanceStatus"] == "available", timeout_s=1800.0, interval_s=20.0)


def _create_snapshot(ctx, db_id: str) -> str:
    rds = ctx.client("rds")
    snap_id = ctx.unique_name("sim2real-rds-snap-")
    rds.create_db_snapshot(
        DBSnapshotIdentifier=snap_id,
        DBInstanceIdentifier=db_id,
        Tags=[{"Key": "sim2real", "Value": "rds-s3-behavioral"}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_snapshot(DBSnapshotIdentifier=snap_id))

    def probe():
        return rds.describe_db_snapshots(DBSnapshotIdentifier=snap_id)["DBSnapshots"][0]

    snap = _poll_until(probe, lambda s: s["Status"] == "available", timeout_s=1800.0, interval_s=20.0)
    return snap["DBSnapshotArn"]


def _cancel_export_task(rds, task_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        rds.cancel_export_task(ExportTaskIdentifier=task_id)
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
