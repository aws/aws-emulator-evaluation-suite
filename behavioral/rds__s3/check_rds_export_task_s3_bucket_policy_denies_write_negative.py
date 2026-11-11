"""rds-export-task-s3-bucket-policy-denies-write-negative."""
from __future__ import annotations

import json
import secrets
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rds-export-task-s3-bucket-policy-denies-write-negative"
GROUP = "overly-permissive"
SERVICES = ["rds", "s3"]

EXPORT_PRINCIPAL = "export.rds.amazonaws.com"


@tags(
    "axis:rejection",
    "cap:c4",
    "cap:c7",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """StartExportTask with a fully permitted role that the bucket policy denies s3:PutObject* fails at once
    with IamRoleMissingPermissions naming s3:PutObject and writes nothing, while a second role the Deny
    does not name completes the same export against the same bucket."""
    rds = ctx.client("rds")
    s3 = ctx.client("s3")

    bucket = _create_bucket(ctx)
    key_arn = _create_kms_key(ctx)
    snapshot_arn = _provision_seeded_snapshot(ctx)

    denied_role_arn = _create_export_role(ctx, EXPORT_PRINCIPAL, bucket, key_arn, grant_permissions=True)
    allowed_role_arn = _create_export_role(ctx, EXPORT_PRINCIPAL, bucket, key_arn, grant_permissions=True)

    _put_bucket_policy_with_retry(
        s3,
        bucket,
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DenyExportRolePut",
                    "Effect": "Deny",
                    "Principal": {"AWS": denied_role_arn},
                    "Action": "s3:PutObject*",
                    "Resource": f"arn:aws:s3:::{bucket}/*",
                }
            ],
        },
    )

    denied_task_id = ctx.unique_name("sim2real-export-denied-")
    denied_prefix = "bucket-policy-denied"
    # RDS probes the role's effective S3 write access at StartExportTask call time
    # (before ever creating a pollable task), so a bucket-policy Deny surfaces as a
    # synchronous ClientError rather than an async FAILED task.
    try:
        rds.start_export_task(
            ExportTaskIdentifier=denied_task_id,
            SourceArn=snapshot_arn,
            S3BucketName=bucket,
            IamRoleArn=denied_role_arn,
            KmsKeyId=key_arn,
            S3Prefix=denied_prefix,
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "IamRoleMissingPermissions", (
            f"unexpected error code for a role denied by bucket policy: {code}: {exc}"
        )
        message = exc.response["Error"].get("Message", "")
        expected = f"The IAM role {denied_role_arn} isn't authorized to call s3:PutObject on the S3 bucket {bucket}."
        assert message == expected, f"IamRoleMissingPermissions message {message!r} != {expected!r}"
    else:
        raise AssertionError(
            "StartExportTask unexpectedly accepted a role whose writes the "
            "destination bucket policy explicitly denies"
        )
    denied_objects = s3.list_objects_v2(Bucket=bucket, Prefix=denied_prefix).get("Contents", [])
    assert denied_objects == [], f"objects should not exist when the bucket policy denies writes: {denied_objects}"

    # Positive control: a different role, not named in the Deny statement,
    # completes the same export against the same bucket.
    allowed_task_id = ctx.unique_name("sim2real-export-allowed-")
    allowed_prefix = "bucket-policy-allowed"
    _start_export_task_with_retry(
        rds,
        ExportTaskIdentifier=allowed_task_id,
        SourceArn=snapshot_arn,
        S3BucketName=bucket,
        IamRoleArn=allowed_role_arn,
        KmsKeyId=key_arn,
        S3Prefix=allowed_prefix,
    )
    allowed_task = _poll_until(
        lambda: rds.describe_export_tasks(ExportTaskIdentifier=allowed_task_id)["ExportTasks"][0],
        lambda t: t["Status"] in ("COMPLETE", "FAILED", "CANCELED"),
        timeout_s=1800,
        interval_s=20,
    )
    assert allowed_task["Status"] == "COMPLETE", f"positive control did not complete: {allowed_task}"
    allowed_objects = s3.list_objects_v2(Bucket=bucket, Prefix=allowed_prefix).get("Contents", [])
    assert allowed_objects, "positive control completed but wrote no objects to S3"


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
            "NoSuchBucket",
            "NoSuchEntity",
            "NotFoundException",
        ):
            raise


def _random_password() -> str:
    return "Aa1" + secrets.token_urlsafe(14)


def _put_bucket_policy_with_retry(s3, bucket: str, policy_doc: dict, timeout_s: float = 60.0) -> None:
    # A bucket policy naming a just-created role as Principal can transiently fail with
    # MalformedPolicy ("Invalid principal in policy") until the role propagates through
    # IAM; retry only that specific, transient rejection, bounded.
    deadline = time.monotonic() + timeout_s
    last_err: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy_doc))
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"].get("Message", "")
            if code == "MalformedPolicy" and "principal" in msg.lower():
                last_err = exc
                time.sleep(5)
                continue
            raise
    raise AssertionError(f"bucket policy referencing a fresh role still rejected after IAM propagation window: {last_err}")


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-rdss3-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "rds-s3-behavioral"}]})
    ctx.on_cleanup(lambda: _best_effort(lambda: _empty_and_delete_bucket(ctx, name)))
    return name


def _empty_and_delete_bucket(ctx, name: str) -> None:
    s3 = ctx.client("s3")
    # Clear the Deny bucket policy first; some accounts refuse delete_bucket
    # via the same principal that a policy statement denies against.
    try:
        s3.delete_bucket_policy(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
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


def _start_export_task_with_retry(rds, *, timeout_s: float = 120.0, interval_s: float = 10.0, **kwargs) -> None:
    # A freshly granted identity policy can take a few seconds to propagate before RDS's
    # own permission probe at StartExportTask time sees it; retry only that specific,
    # transient rejection, bounded.
    deadline = time.monotonic() + timeout_s
    last_err: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            rds.start_export_task(**kwargs)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("IamRoleMissingPermissions", "InvalidParameterValue"):
                last_err = exc
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"positive control still rejected after IAM propagation window: {last_err}")


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
