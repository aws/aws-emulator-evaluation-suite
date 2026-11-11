"""rds-export-task-nonexistent-bucket-negative."""
from __future__ import annotations

import json
import time
import uuid
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rds-export-task-nonexistent-bucket-negative"
GROUP = "permission-boundary"
SERVICES = ["rds", "s3"]

FULL_S3_ACTIONS = [
    "s3:PutObject*",
    "s3:GetObject*",
    "s3:ListBucket",
    "s3:DeleteObject*",
    "s3:GetBucketLocation",
]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartExportTask against a bucket that doesn't exist is rejected and creates nothing."""
    kms_key_arn = _create_kms_key(ctx)
    snapshot_arn = _create_snapshot_source(ctx)
    rds = ctx.client("rds")
    s3 = ctx.client("s3")

    # A bucket name that was never created via s3:CreateBucket.
    missing_bucket = ctx.unique_name("sim2real-rds-export-missing-")
    role_arn = _create_export_role(
        ctx, "export.rds.amazonaws.com", missing_bucket, kms_key_arn, FULL_S3_ACTIONS
    )
    bad_export_id = ctx.unique_name("sim2real-export-bad-")

    error = _client_error_with_retry(
        lambda: rds.start_export_task(
            ExportTaskIdentifier=bad_export_id,
            SourceArn=snapshot_arn,
            S3BucketName=missing_bucket,
            IamRoleArn=role_arn,
            KmsKeyId=kms_key_arn,
        ),
        retryable_codes=("KMSKeyNotAccessibleFault",),
    )
    assert error.get("Code") == "InvalidS3BucketFault", error
    expected_message = (
        f"The S3 bucket {missing_bucket} isn't valid. Either it isn't located in the current "
        "AWS Region or it doesn't exist."
    )
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # Effect absent: the rejected call must not have silently created the target bucket.
    # HeadBucket carries no error body, so the status code is the whole answer.
    head_code = _client_error_with_retry(lambda: s3.head_bucket(Bucket=missing_bucket), ()).get("Code")
    assert head_code == "404", head_code

    # Positive control: identical role/snapshot, but against a bucket that really exists.
    real_bucket = _create_bucket(ctx)
    good_role_arn = _create_export_role(
        ctx, "export.rds.amazonaws.com", real_bucket, kms_key_arn, FULL_S3_ACTIONS
    )
    good_export_id = ctx.unique_name("sim2real-export-good-")
    _start_export_task_with_retry(
        rds,
        ExportTaskIdentifier=good_export_id,
        SourceArn=snapshot_arn,
        S3BucketName=real_bucket,
        IamRoleArn=good_role_arn,
        KmsKeyId=kms_key_arn,
    )
    ctx.on_cleanup(lambda: _cancel_export_task_ignore(rds, good_export_id))
    # Independent read at the destination: the control must actually complete and
    # deliver bytes, not merely be accepted by the mutating call's own response.
    good_task = _poll_until(
        lambda: rds.describe_export_tasks(ExportTaskIdentifier=good_export_id)["ExportTasks"][0],
        lambda t: t["Status"] in ("COMPLETE", "FAILED", "CANCELED"),
        timeout_s=2400.0,
        interval_s=20.0,
        description=f"export task {good_export_id} to reach a terminal state",
    )
    assert good_task["Status"] == "COMPLETE", (
        f"positive control export ended in {good_task['Status']!r}: {good_task.get('FailureCause')}"
    )
    delivered = s3.list_objects_v2(Bucket=real_bucket).get("Contents", [])
    assert delivered, "control export completed but produced no S3 objects in the real bucket"


def _client_error_with_retry(fn, retryable_codes, timeout_s=90.0, interval_s=5.0) -> dict:
    """Call fn() and return the botocore Error dict it raises, retrying while the code is one
    of *retryable_codes* -- IAM/KMS grants attached moments earlier can transiently surface as
    KMSKeyNotAccessibleFault before they propagate, which would otherwise mask the real,
    persistent rejection (e.g. InvalidS3BucketFault) this check is asserting on. An
    unexpected success raises AssertionError."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as err:
            error = err.response.get("Error", {})
            if error.get("Code") in retryable_codes and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            return error
        raise AssertionError(f"call unexpectedly succeeded instead of being rejected: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=5.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description}; last observed: {last!r}")


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-rds-export-")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _cleanup() -> None:
        resp = s3.list_objects_v2(Bucket=name)
        objs = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
        if objs:
            failed = s3.delete_objects(Bucket=name, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _create_kms_key(ctx) -> str:
    kms = ctx.client("kms")
    key = kms.create_key(
        Description="sim2real rds export key",
        Tags=[{"TagKey": "sim2real", "TagValue": "rds-s3-behavioral"}],
    )["KeyMetadata"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key["KeyId"], PendingWindowInDays=7))
    return key["Arn"]


def _create_export_role(
    ctx, trust_service, bucket_name=None, kms_key_arn=None, s3_actions=None
) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-rds-export-role-")
    trust_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": trust_service},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_doc)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    if s3_actions and bucket_name:
        statements = [
            {
                "Effect": "Allow",
                "Action": s3_actions,
                "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
            }
        ]
        if kms_key_arn:
            statements.append(
                {
                    "Effect": "Allow",
                    "Action": ["kms:CreateGrant", "kms:DescribeKey"],
                    "Resource": kms_key_arn,
                }
            )
        policy_name = ctx.unique_name("sim2real-rds-export-policy-")
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_snapshot_source(ctx) -> str:
    rds = ctx.client("rds")
    db_id = ctx.unique_name("sim2real-rds-src-")
    password = f"S2r{uuid.uuid4().hex[:16]}Aa1"
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=db_id,
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        AllocatedStorage=20,
        MasterUsername="s2ruser",
        MasterUserPassword=password,
        PubliclyAccessible=False,
        BackupRetentionPeriod=1,
        StorageType="gp2",
        Tags=[{"Key": "sim2real", "Value": "rds-s3-behavioral"}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_instance(DBInstanceIdentifier=db_id, SkipFinalSnapshot=True)
    )
    _poll_until(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0][
            "DBInstanceStatus"
        ],
        lambda status: status == "available",
        timeout_s=1800,
        interval_s=20,
        description=f"db instance {db_id} available",
    )
    snap_id = ctx.unique_name("sim2real-rds-snap-")
    rds.create_db_snapshot(DBSnapshotIdentifier=snap_id, DBInstanceIdentifier=db_id)
    ctx.on_cleanup(lambda: rds.delete_db_snapshot(DBSnapshotIdentifier=snap_id))
    final = _poll_until(
        lambda: rds.describe_db_snapshots(DBSnapshotIdentifier=snap_id)["DBSnapshots"][0],
        lambda snap: snap["Status"] == "available",
        timeout_s=1200,
        interval_s=15,
        description=f"snapshot {snap_id} available",
    )
    return final["DBSnapshotArn"]


def _start_export_task_with_retry(rds, timeout_s=90.0, **kwargs):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return rds.start_export_task(**kwargs)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if (
                code in ("IamRoleMissingPermissions", "AccessDenied", "KMSKeyNotAccessibleFault")
                and time.monotonic() < deadline
            ):
                time.sleep(5)
                continue
            raise



def _cancel_export_task_ignore(rds, export_task_id) -> None:
    try:
        rds.cancel_export_task(ExportTaskIdentifier=export_task_id)
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
