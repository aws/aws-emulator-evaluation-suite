"""rds-snapshot-export-missing-s3-permission-negative."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rds-snapshot-export-missing-s3-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["rds", "s3"]


@tags(
    "axis:rejection",
    "cap:c4",
    "cap:c7",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "concern:representation",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """StartExportTask rejects a correctly-trusted role lacking s3:PutObject with
    IamRoleMissingPermissions, leaving no task record (DescribeExportTasks lists none) and no
    bytes, while the same call with a fully-permissioned role completes and delivers objects."""
    bucket = _create_bucket(ctx)
    key_id, key_arn = _create_kms_key(ctx)
    snapshot_arn = _create_snapshot(ctx)
    # Correctly trusted, but missing ONLY s3:PutObject* on the target bucket.
    restricted_role_arn = _create_export_role(
        ctx, bucket, key_arn, missing_actions=["s3:PutObject*"]
    )
    full_role_arn = _create_export_role(ctx, bucket, key_arn)

    rds = ctx.client("rds")
    s3 = ctx.client("s3")

    bad_task_id = ctx.unique_name("sim2real-exp-bad-")
    code, message = _start_export_task_rejection(
        rds,
        retryable_codes=("KMSKeyNotAccessibleFault", "IamRoleNotFoundFault"),
        ExportTaskIdentifier=bad_task_id,
        SourceArn=snapshot_arn,
        S3BucketName=bucket,
        IamRoleArn=restricted_role_arn,
        KmsKeyId=key_id,
    )
    assert code == "IamRoleMissingPermissions", (
        f"expected StartExportTask with a PutObject-less role to be rejected with "
        f"IamRoleMissingPermissions, got {code!r}"
    )
    expected_message = (
        f"The IAM role {restricted_role_arn} isn't authorized to call s3:PutObject "
        f"on the S3 bucket {bucket}."
    )
    assert message == expected_message, (
        f"expected StartExportTask refusal message {expected_message!r}, got {message!r}"
    )

    # Effect absent, at the destination: StartExportTask itself was rejected, so DescribeExportTasks
    # answers with a 200 and an empty ExportTasks list (not ExportTaskNotFoundFault or a FAILED
    # record), and no bytes landed in the bucket.
    bad_tasks = rds.describe_export_tasks(ExportTaskIdentifier=bad_task_id).get(
        "ExportTasks", []
    )
    assert bad_tasks == [], (
        f"expected the rejected call to leave no export task record, got {bad_tasks!r}"
    )
    bad_objects = s3.list_objects_v2(Bucket=bucket, Prefix=bad_task_id).get(
        "Contents", []
    )
    assert bad_objects == [], (
        f"S3 received objects despite the rejected export task: {bad_objects}"
    )

    # Positive control: the same snapshot, bucket and KMS key, but a role that also has
    # s3:PutObject, is accepted, runs to completion and delivers real objects.
    good_task_id = ctx.unique_name("sim2real-exp-good-")
    good_start = _start_export_task_with_retry(
        rds,
        ExportTaskIdentifier=good_task_id,
        SourceArn=snapshot_arn,
        S3BucketName=bucket,
        IamRoleArn=full_role_arn,
        KmsKeyId=key_id,
    )
    ctx.on_cleanup(lambda: _cancel_export_task_ignore(rds, good_task_id))
    assert good_start["Status"] in ("STARTING", "IN_PROGRESS"), (
        f"expected the fully-permissioned export task to start, got {good_start['Status']!r}"
    )

    good_task = _poll_until(
        lambda: rds.describe_export_tasks(ExportTaskIdentifier=good_task_id)[
            "ExportTasks"
        ][0],
        lambda t: t["Status"] in ("COMPLETE", "FAILED", "CANCELED"),
        timeout_s=2400,
        interval_s=30,
    )
    assert good_task["Status"] == "COMPLETE", (
        f"positive control export ended in {good_task['Status']}: {good_task.get('FailureCause')}"
    )
    good_objects = s3.list_objects_v2(Bucket=bucket, Prefix=good_task_id).get(
        "Contents", []
    )
    assert len(good_objects) > 0, (
        "positive control export completed but delivered no objects"
    )


# ===== helpers =====
def _poll_until(probe, predicate, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-rds-exp-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )

    def _cleanup():
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=name):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _create_kms_key(ctx) -> tuple[str, str]:
    kms = ctx.client("kms")
    key = kms.create_key(Description="sim2real rds export test key")["KeyMetadata"]
    ctx.on_cleanup(
        lambda: kms.schedule_key_deletion(KeyId=key["KeyId"], PendingWindowInDays=7)
    )
    return key["KeyId"], key["Arn"]


_ALL_S3_ACTIONS = [
    "s3:PutObject*",
    "s3:GetObject*",
    "s3:ListBucket",
    "s3:DeleteObject*",
    "s3:GetBucketLocation",
]
_KMS_EXPORT_ACTIONS = ["kms:CreateGrant", "kms:DescribeKey"]


def _create_export_role(ctx, bucket_name, key_arn, *, missing_actions=None) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-rds-export-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "export.rds.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    missing = set(missing_actions or [])
    s3_actions = [a for a in _ALL_S3_ACTIONS if a not in missing]
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "S3Export",
                "Effect": "Allow",
                "Action": s3_actions,
                "Resource": [
                    f"arn:aws:s3:::{bucket_name}",
                    f"arn:aws:s3:::{bucket_name}/*",
                ],
            },
            {
                "Sid": "KmsExport",
                "Effect": "Allow",
                "Action": _KMS_EXPORT_ACTIONS,
                "Resource": key_arn,
            },
        ],
    }
    policy_name = ctx.unique_name("sim2real-rds-export-policy-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(policy_doc),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    )
    return role_arn


def _create_snapshot(ctx) -> str:
    rds = ctx.client("rds")
    db_id = ctx.unique_name("sim2real-rds-exp-db-")
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=db_id,
        Engine="mysql",
        DBInstanceClass="db.t3.micro",
        AllocatedStorage=20,
        MasterUsername="s2ruser",
        MasterUserPassword="S2rTestPassw0rd1",
        BackupRetentionPeriod=0,
        PubliclyAccessible=False,
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_instance(
            DBInstanceIdentifier=db_id, SkipFinalSnapshot=True
        )
    )
    _poll_until(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0][
            "DBInstanceStatus"
        ],
        lambda s: s == "available",
        timeout_s=1800,
        interval_s=30,
    )

    snap_id = ctx.unique_name("sim2real-rds-exp-snap-")
    rds.create_db_snapshot(DBSnapshotIdentifier=snap_id, DBInstanceIdentifier=db_id)
    ctx.on_cleanup(lambda: rds.delete_db_snapshot(DBSnapshotIdentifier=snap_id))
    snap = _poll_until(
        lambda: rds.describe_db_snapshots(DBSnapshotIdentifier=snap_id)["DBSnapshots"][
            0
        ],
        lambda s: s["Status"] == "available",
        timeout_s=1800,
        interval_s=30,
    )
    return snap["DBSnapshotArn"]


def _start_export_task_rejection(
    rds, *, retryable_codes=(), timeout_s=90.0, interval_s=5.0, **kwargs
):
    """Call StartExportTask and return the (code, message) of the ClientError it raises, retrying only while the
    code is a transient IAM/KMS propagation fault rather than the persistent rejection under
    test. Raises on unexpected success so an accepted call is reported as such, not as a code
    mismatch."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            resp = rds.start_export_task(**kwargs)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in retryable_codes and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            return code, err.response["Error"].get("Message")
        else:
            raise AssertionError(
                f"expected StartExportTask to be rejected, but it started task "
                f"{kwargs.get('ExportTaskIdentifier')!r} with status {resp.get('Status')!r}"
            )


def _start_export_task_with_retry(rds, *, timeout_s=90.0, interval_s=5.0, **kwargs):
    """IAM is eventually consistent: retry StartExportTask, bounded, while it reports the
    just-granted role/key as not yet usable."""
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
                    "IamRoleNotFoundFault",
                    "AccessDenied",
                    "KMSKeyNotAccessibleFault",
                )
                and time.monotonic() < deadline
            ):
                time.sleep(interval_s)
                continue
            raise


def _cancel_export_task_ignore(rds, export_task_id) -> None:
    # A missing task, or one already COMPLETE/FAILED/CANCELED, has nothing left to cancel.
    try:
        rds.cancel_export_task(ExportTaskIdentifier=export_task_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ExportTaskNotFound", "InvalidExportTaskStateFault"):
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
