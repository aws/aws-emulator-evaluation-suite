"""rds-iam-role-trust-s3-service-positive."""
from __future__ import annotations

import json
import secrets
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rds-iam-role-trust-s3-service-positive"
GROUP = "iam-trust"
SERVICES = ["rds", "s3"]

# Per AWS docs (USER_ExportSnapshot.html, "Providing access to an Amazon S3
# bucket using an IAM role"), the RDS-S3 export pipeline's IAM role must trust
# the *export.rds.amazonaws.com* service principal -- not s3.amazonaws.com --
# because it is the RDS export task (not S3) that assumes the role. With that
# principal the export task assumes the role, completes, and writes data to S3.
EXPORT_PRINCIPAL = "export.rds.amazonaws.com"


@tags(
    "axis:happy-path",
    "cap:c4",
    "cap:c7",
    "concern:data-plane",
    "concern:e2e",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """An IAM role whose AssumeRolePolicyDocument trusts export.rds.amazonaws.com
    is accepted by RDS as the export role: StartExportTask can assume it, and
    the export task reaches COMPLETE without any assume-role failure."""
    rds = ctx.client("rds")
    s3 = ctx.client("s3")

    bucket = _create_bucket(ctx)
    key_arn = _create_kms_key(ctx)
    snapshot_arn = _provision_seeded_snapshot(ctx)
    role_arn = _create_export_role(ctx, EXPORT_PRINCIPAL, bucket, key_arn, grant_permissions=True)

    task_id = ctx.unique_name("sim2real-export-")
    prefix = "trust-positive"
    _start_export_task_with_retry(
        rds,
        ExportTaskIdentifier=task_id,
        SourceArn=snapshot_arn,
        S3BucketName=bucket,
        IamRoleArn=role_arn,
        KmsKeyId=key_arn,
        S3Prefix=prefix,
    )

    task = _poll_until(
        lambda: rds.describe_export_tasks(ExportTaskIdentifier=task_id)["ExportTasks"][0],
        lambda t: t["Status"] in ("COMPLETE", "FAILED", "CANCELED"),
        timeout_s=1800,
        interval_s=20,
    )
    assert task["Status"] == "COMPLETE", (
        f"export task with a role trusting {EXPORT_PRINCIPAL} did not complete "
        f"(role assumption should have succeeded): {task}"
    )
    assert not task.get("FailureCause"), f"unexpected FailureCause: {task.get('FailureCause')}"
    assert task["IamRoleArn"] == role_arn, (
        f"export task recorded IamRoleArn={task['IamRoleArn']!r}, expected {role_arn!r}"
    )

    objects = s3.list_objects_v2(Bucket=bucket, Prefix=prefix).get("Contents", [])
    assert objects, "role trust was accepted but no objects were written to S3"


def _poll_until(probe, predicate, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _start_export_task_with_retry(rds, timeout_s: float = 180.0, interval_s: float = 10.0, **kwargs) -> None:
    """A trust policy or role-policy attachment just written by ``iam.put_role_policy`` /
    ``iam.create_role`` is not always visible to RDS -- or to KMS's policy evaluation for that
    role's just-granted ``kms:CreateGrant``/``kms:DescribeKey`` -- on the very next call. That is
    IAM's own eventual consistency, and it can surface as KMSKeyNotAccessibleFault as well as an
    Iam*Fault, so the call is retried on those specific faults."""
    from botocore.exceptions import ClientError

    retryable = (
        "IamRoleNotFoundFault",
        "IamRoleMissingPermissionsFault",
        "KMSKeyNotAccessibleFault",
    )
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            rds.start_export_task(**kwargs)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in retryable or time.monotonic() > deadline:
                raise
            time.sleep(interval_s)


def _best_effort(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "DBInstanceNotFound",
            "DBSnapshotNotFound",
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
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "rds-s3-behavioral"}]}
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


def _create_export_role(
    ctx, principal: str, bucket_name: str | None, key_arn: str | None, grant_permissions: bool
) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-rdss3-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": principal}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "rds-s3-behavioral"}],
    )["Role"]
    ctx.on_cleanup(lambda: _best_effort(lambda: iam.delete_role(RoleName=role_name)))

    if grant_permissions and bucket_name and key_arn:
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
                "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
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


def _provision_seeded_snapshot(ctx) -> str:
    """Create a minimal RDS MySQL instance and a manual snapshot of it, returning the
    snapshot ARN. StartExportTask exports ALL data in the snapshot by default (per AWS
    docs: USER_ExportSnapshot.html, "By default, all data in the snapshot is
    exported"), and every fresh MySQL instance already carries real system-schema
    tables (mysql.*, performance_schema.*, sys.*) with genuine rows -- so the export
    has real data to write to S3 without a native SQL connection to seed a user table
    (the check uses neither a MySQL driver nor the mysql CLI)."""
    rds = ctx.client("rds")
    db_id = ctx.unique_name("sim2real-rdss3-db-")
    password = _random_password()
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=db_id,
        Engine="mysql",
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
            lambda: rds.delete_db_instance(DBInstanceIdentifier=db_id, SkipFinalSnapshot=True)
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
    ctx.on_cleanup(lambda: _best_effort(lambda: rds.delete_db_snapshot(DBSnapshotIdentifier=snap_id)))
    snap = _poll_until(
        lambda: rds.describe_db_snapshots(DBSnapshotIdentifier=snap_id)["DBSnapshots"][0],
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
