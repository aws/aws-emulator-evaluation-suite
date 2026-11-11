"""rds-export-task-role-trusts-export-service-positive."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "rds-export-task-role-trusts-export-service-positive"
GROUP = "permission-boundary"
SERVICES = ["rds", "s3"]


@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """An export task whose role trusts export.rds.amazonaws.com reaches COMPLETE and its
    objects land in S3."""
    bucket = _create_bucket(ctx)
    role_arn = _create_export_role(ctx, bucket, "export.rds.amazonaws.com")
    db_id = _create_encrypted_mysql_instance(ctx)
    _wait_instance_available(ctx, db_id)
    snapshot_arn = _create_snapshot(ctx, db_id)

    rds = ctx.client("rds")
    kms_key_arn = _create_export_kms_key(ctx)
    task_id = ctx.unique_name("sim2real-rds-export-trust-ok-")
    prefix = "trust-ok"
    _start_export_task_with_retry(
        rds,
        ExportTaskIdentifier=task_id,
        SourceArn=snapshot_arn,
        S3BucketName=bucket,
        IamRoleArn=role_arn,
        KmsKeyId=kms_key_arn,
        S3Prefix=prefix,
    )
    ctx.on_cleanup(lambda: _cancel_export_task(rds, task_id))
    task = _wait_export_task(ctx, task_id)
    assert task["Status"] == "COMPLETE", f"export task ended in {task['Status']!r}"
    assert not task.get("FailureCause"), (
        f"export task reported COMPLETE but carries a FailureCause: {task.get('FailureCause')!r}"
    )
    assert task["IamRoleArn"] == role_arn, (
        f"expected the export task to report the trusted role {role_arn!r}, got {task.get('IamRoleArn')!r}"
    )

    keys = _list_export_objects(ctx, bucket, f"{prefix}/{task_id}/")
    assert keys, "export task reported COMPLETE but wrote no S3 objects"


# ===== helpers =====
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
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))
    return name


def _empty_and_delete_bucket(s3, name) -> None:
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=name):
        for obj in page.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
    s3.delete_bucket(Bucket=name)


def _create_export_role(ctx, bucket_name: str, trust_service: str) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-rds-export-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": trust_service},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))[
        "Role"
    ]
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
                "Resource": [
                    f"arn:aws:s3:::{bucket_name}",
                    f"arn:aws:s3:::{bucket_name}/*",
                ],
            }
        ],
    }
    pol_name = ctx.unique_name("sim2real-rds-export-policy-")
    iam.put_role_policy(
        RoleName=name, PolicyName=pol_name, PolicyDocument=json.dumps(policy_doc)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName=pol_name))
    return role["Arn"]


def _create_export_kms_key(ctx) -> str:
    kms = ctx.client("kms")
    key = kms.create_key(
        Description=ctx.unique_name("sim2real-rds-export-kms-"),
        KeyUsage="ENCRYPT_DECRYPT",
        Tags=[{"TagKey": "sim2real", "TagValue": "rds-s3-behavioral"}],
    )["KeyMetadata"]
    ctx.on_cleanup(
        lambda: kms.schedule_key_deletion(KeyId=key["KeyId"], PendingWindowInDays=7)
    )
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
    ctx.on_cleanup(
        lambda: rds.delete_db_instance(
            DBInstanceIdentifier=db_id, SkipFinalSnapshot=True
        )
    )
    return db_id


def _wait_instance_available(ctx, db_id: str) -> dict[str, Any]:
    rds = ctx.client("rds")

    def probe():
        return rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0]

    return _poll_until(
        probe,
        lambda i: i["DBInstanceStatus"] == "available",
        timeout_s=1800.0,
        interval_s=20.0,
    )


def _create_snapshot(ctx, db_id: str) -> str:
    rds = ctx.client("rds")
    snap_id = ctx.unique_name("sim2real-rds-snap-")
    rds.create_db_snapshot(DBSnapshotIdentifier=snap_id, DBInstanceIdentifier=db_id)
    ctx.on_cleanup(lambda: rds.delete_db_snapshot(DBSnapshotIdentifier=snap_id))

    def probe():
        return rds.describe_db_snapshots(DBSnapshotIdentifier=snap_id)["DBSnapshots"][0]

    snap = _poll_until(
        probe, lambda s: s["Status"] == "available", timeout_s=1800.0, interval_s=20.0
    )
    return snap["DBSnapshotArn"]


def _start_export_task_with_retry(rds, **kwargs) -> None:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 90.0
    while True:
        try:
            rds.start_export_task(**kwargs)
            return
        except ClientError as exc:
            if (
                exc.response["Error"]["Code"] != "IamRoleNotFound"
                or time.monotonic() > deadline
            ):
                raise
            time.sleep(2)


def _cancel_export_task(rds, task_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        rds.cancel_export_task(ExportTaskIdentifier=task_id)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "ExportTaskNotFound":
            return
        if code != "InvalidExportTaskStateFault":
            raise
        # A finished export refuses cancellation; only a task still running is a teardown failure.
        status = rds.describe_export_tasks(ExportTaskIdentifier=task_id)["ExportTasks"][0]["Status"]
        if status not in ("COMPLETE", "FAILED", "CANCELED", "CANCELING"):
            raise


def _wait_export_task(ctx, task_id: str, timeout_s: float = 2400.0) -> dict[str, Any]:
    rds = ctx.client("rds")
    terminal = {"COMPLETE", "FAILED", "CANCELED"}

    def probe():
        return rds.describe_export_tasks(ExportTaskIdentifier=task_id)["ExportTasks"][0]

    return _poll_until(
        probe, lambda t: t["Status"] in terminal, timeout_s=timeout_s, interval_s=20.0
    )


def _list_export_objects(ctx, bucket: str, prefix: str) -> list[str]:
    s3 = ctx.client("s3")
    keys: list[str] = []
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            keys.append(obj["Key"])
    return keys


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
