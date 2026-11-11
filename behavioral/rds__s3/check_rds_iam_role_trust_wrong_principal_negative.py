"""rds-iam-role-trust-wrong-principal-negative."""
from __future__ import annotations

import json
import secrets
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rds-iam-role-trust-wrong-principal-negative"
GROUP = "overly-permissive"
SERVICES = ["rds", "s3"]

EXPORT_PRINCIPAL = "export.rds.amazonaws.com"
WRONG_PRINCIPAL = "ec2.amazonaws.com"


@tags(
    "axis:rejection",
    "cap:c4",
    "cap:c7",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """StartExportTask rejects at once a role with the right S3 and KMS permissions that trusts
    ec2.amazonaws.com, not export.rds.amazonaws.com, and writes nothing, while a role with identical
    permissions and the correct trust principal completes the same export to the same bucket."""
    rds = ctx.client("rds")
    s3 = ctx.client("s3")

    bucket = _create_bucket(ctx)
    key_arn = _create_kms_key(ctx)
    snapshot_arn = _provision_seeded_snapshot(ctx)

    wrong_trust_role_arn = _create_export_role(
        ctx, WRONG_PRINCIPAL, bucket, key_arn, grant_permissions=True
    )
    correct_trust_role_arn = _create_export_role(
        ctx, EXPORT_PRINCIPAL, bucket, key_arn, grant_permissions=True
    )

    wrong_task_id = ctx.unique_name("sim2real-export-wrongtrust-")
    wrong_prefix = "wrong-trust-principal"
    # RDS validates that the export principal can assume the role SYNCHRONOUSLY at
    # StartExportTask call time (it never creates a task to poll to FAILED) when the
    # trust policy names the wrong principal. KMSKeyNotAccessibleFault is retried while IAM/KMS
    # propagate.
    kms_deadline = time.monotonic() + 180.0
    while True:
        try:
            rds.start_export_task(
                ExportTaskIdentifier=wrong_task_id,
                SourceArn=snapshot_arn,
                S3BucketName=bucket,
                IamRoleArn=wrong_trust_role_arn,
                KmsKeyId=key_arn,
                S3Prefix=wrong_prefix,
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "KMSKeyNotAccessibleFault" and time.monotonic() < kms_deadline:
                time.sleep(2)
                continue
            error = exc
        else:
            error = None
        break
    if error is not None:
        code = error.response["Error"]["Code"]
        message = error.response["Error"].get("Message", "")
        assert code == "IamRoleNotFound", f"unexpected error code for a role with a wrong trust principal: {code}: {error}"
        expected = (
            f"The principal {EXPORT_PRINCIPAL} isn't allowed to assume the IAM role {wrong_trust_role_arn} "
            f"or the IAM role {wrong_trust_role_arn} doesn't exist."
        )
        assert message == expected, f"expected message {expected!r}, got {message!r}"
    else:
        raise AssertionError(
            "StartExportTask unexpectedly accepted a role whose trust policy names "
            f"{WRONG_PRINCIPAL} instead of {EXPORT_PRINCIPAL}"
        )
    wrong_objects = s3.list_objects_v2(Bucket=bucket, Prefix=wrong_prefix).get("Contents", [])
    assert wrong_objects == [], f"objects should not exist when the role cannot be assumed: {wrong_objects}"

    # Positive control: identical permissions, correct trust principal. IAM role trust
    # changes can take a few seconds to propagate to RDS's control plane, so retry on
    # IamRoleNotFound specifically (never on any other code) within a bounded deadline.
    correct_task_id = ctx.unique_name("sim2real-export-correcttrust-")
    correct_prefix = "correct-trust-principal"
    _start_export_task_with_retry(
        rds,
        ExportTaskIdentifier=correct_task_id,
        SourceArn=snapshot_arn,
        S3BucketName=bucket,
        IamRoleArn=correct_trust_role_arn,
        KmsKeyId=key_arn,
        S3Prefix=correct_prefix,
    )
    correct_task = _poll_until(
        lambda: rds.describe_export_tasks(ExportTaskIdentifier=correct_task_id)["ExportTasks"][0],
        lambda t: t["Status"] in ("COMPLETE", "FAILED", "CANCELED"),
        timeout_s=1800,
        interval_s=20,
    )
    assert correct_task["Status"] == "COMPLETE", f"positive control did not complete: {correct_task}"
    correct_objects = s3.list_objects_v2(Bucket=bucket, Prefix=correct_prefix).get("Contents", [])
    assert correct_objects, "positive control completed but wrote no objects to S3"


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


def _start_export_task_with_retry(rds, timeout_s: float = 90.0, interval_s: float = 10.0, **kwargs) -> None:
    # While a just-created role's trust policy is still
    # propagating, RDS's inability to assume it surfaces as either IamRoleNotFound
    # (it cannot find/assume the role) or KMSKeyNotAccessibleFault (it cannot use the
    # unassumable role to check KMS grant access) -- both are retryable here because
    # this role's trust principal is in fact correct and propagation is transient.
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            rds.start_export_task(**kwargs)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("IamRoleNotFound", "KMSKeyNotAccessibleFault") or time.monotonic() > deadline:
                raise
            time.sleep(interval_s)


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
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "rds-s3-behavioral"}]})
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
