"""rds-export-task-wrong-bucket-negative."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError
import uuid

import botocore.exceptions

from behavioral_harness import tags

CHECK = "rds-export-task-wrong-bucket-negative"
GROUP = "snapshot-export"
SERVICES = ["rds", "s3"]


@tags(
    "axis:rejection",
    "cap:c4",
    "cap:c7",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """StartExportTask with a role granted only bucket A, targeting existing bucket B, fails with
    IamRoleMissingPermissions naming s3:GetBucketLocation on B and writes nothing there, while the same
    role targeting bucket A is accepted and described as started."""
    rds = ctx.client("rds")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    kms = ctx.client("kms")

    bucket_authorized = _create_bucket(ctx, s3)
    bucket_unauthorized = _create_bucket(ctx, s3)
    key_arn = _create_kms_key(ctx, kms)
    snapshot_arn = _create_snapshot(ctx, rds)

    # Role scoped, by resource ARN, only to bucket_authorized.
    role_arn = _create_export_role(ctx, iam, bucket_authorized, key_arn)

    wrong_task_id = ctx.unique_name("sim2real-rds-export-wrongbkt-")
    error = _start_export_task_expect_error(
        rds,
        ExportTaskIdentifier=wrong_task_id,
        SourceArn=snapshot_arn,
        S3BucketName=bucket_unauthorized,
        IamRoleArn=role_arn,
        KmsKeyId=key_arn,
    )
    assert error.get("Code") == "IamRoleMissingPermissions", (
        f"expected IamRoleMissingPermissions targeting a bucket the role has no grant on, got {error!r}"
    )
    # RDS probes s3:GetBucketLocation first, and the role holds no grant on this bucket at all.
    expected_message = (
        f"The IAM role {role_arn} isn't authorized to call s3:GetBucketLocation "
        f"on the S3 bucket {bucket_unauthorized}."
    )
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )
    written = _list_objects(s3, bucket_unauthorized, prefix=f"{wrong_task_id}/")
    assert written == [], (
        f"expected no objects under {wrong_task_id}/ in the unauthorized bucket, found {written!r}"
    )

    # Positive control: same role/snapshot/key, targeting the bucket it IS
    # authorized for -> StartExportTask must be accepted.
    right_task_id = ctx.unique_name("sim2real-rds-export-rightbkt-")
    resp = _start_export_task_with_retry(
        rds,
        ExportTaskIdentifier=right_task_id,
        SourceArn=snapshot_arn,
        S3BucketName=bucket_authorized,
        IamRoleArn=role_arn,
        KmsKeyId=key_arn,
    )
    ctx.on_cleanup(lambda: _cancel_export_task_quietly(rds, right_task_id))
    assert resp["Status"] in ("STARTING", "IN_PROGRESS", "COMPLETE"), resp["Status"]

    # Independent read at the destination, not the mutating call's own response.
    described = rds.describe_export_tasks(ExportTaskIdentifier=right_task_id)["ExportTasks"][0]
    assert described["Status"] in ("STARTING", "IN_PROGRESS", "COMPLETE"), (
        f"expected the authorized-bucket export to be accepted, describe_export_tasks reports "
        f"{described['Status']!r}"
    )


def _create_bucket(ctx, s3):
    bucket = ctx.unique_name("sim2real-rds-export-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    return bucket


def _empty_and_delete_bucket(s3, bucket):
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        contents = page.get("Contents", [])
        if contents:
            failed = s3.delete_objects(
                Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in contents]}
            ).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _create_kms_key(ctx, kms):
    key = kms.create_key(
        Description="sim2real RDS snapshot export test key",
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
    )
    key_id = key["KeyMetadata"]["KeyId"]
    key_arn = key["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    return key_arn


def _create_export_role(ctx, iam, bucket, key_arn, *, s3_actions=None, extra_kms=True):
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "export.rds.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_name = ctx.unique_name("sim2real-rds-exp-role-")
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    statements = [
        {
            "Sid": "S3Access",
            "Effect": "Allow",
            "Action": s3_actions
            if s3_actions is not None
            else [
                "s3:PutObject*",
                "s3:ListBucket",
                "s3:GetObject*",
                "s3:DeleteObject*",
                "s3:GetBucketLocation",
            ],
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        }
    ]
    if extra_kms:
        statements.append(
            {
                "Sid": "KmsAccess",
                "Effect": "Allow",
                "Action": ["kms:CreateGrant", "kms:DescribeKey"],
                "Resource": key_arn,
            }
        )
    policy_name = f"{role_name}-policy"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_snapshot(ctx, rds):
    instance_id = ctx.unique_name("sim2real-rds-exp-")
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=instance_id,
        DBInstanceClass="db.t3.micro",
        Engine="mysql",
        MasterUsername="simadmin",
        MasterUserPassword="Sim2Real-" + uuid.uuid4().hex[:12],
        AllocatedStorage=20,
        BackupRetentionPeriod=0,
        StorageType="gp2",
        PubliclyAccessible=False,
        MultiAZ=False,
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_instance(DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True)
    )
    _wait_db_instance_available(rds, instance_id)

    snapshot_id = ctx.unique_name("sim2real-rds-exp-snap-")
    rds.create_db_snapshot(DBSnapshotIdentifier=snapshot_id, DBInstanceIdentifier=instance_id)
    ctx.on_cleanup(lambda: rds.delete_db_snapshot(DBSnapshotIdentifier=snapshot_id))
    snapshot = _wait_snapshot_available(rds, snapshot_id)
    return snapshot["DBSnapshotArn"]


def _wait_db_instance_available(rds, instance_id, timeout_s=2400.0, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        resp = rds.describe_db_instances(DBInstanceIdentifier=instance_id)
        status = resp["DBInstances"][0]["DBInstanceStatus"]
        if status == "available":
            return resp["DBInstances"][0]
        if status in ("failed", "incompatible-parameters", "incompatible-network"):
            raise AssertionError(f"DB instance {instance_id} entered terminal status {status}")
        time.sleep(interval_s)
    raise AssertionError(
        f"DB instance {instance_id} did not become available within {timeout_s}s (last={status})"
    )


def _wait_snapshot_available(rds, snapshot_id, timeout_s=1800.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        resp = rds.describe_db_snapshots(DBSnapshotIdentifier=snapshot_id)
        snap = resp["DBSnapshots"][0]
        status = snap["Status"]
        if status == "available":
            return snap
        if status == "failed":
            raise AssertionError(f"snapshot {snapshot_id} failed")
        time.sleep(interval_s)
    raise AssertionError(
        f"snapshot {snapshot_id} did not become available within {timeout_s}s (last={status})"
    )


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
            if code in ("IamRoleMissingPermissions", "InvalidS3BucketFault", "KMSKeyNotAccessibleFault"):
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _start_export_task_expect_error(rds, *, timeout_s=90.0, interval_s=15.0, **kwargs):
    """Calls StartExportTask, retrying only long enough to rule out transient
    IAM/KMS propagation delay, and returns the (stable) botocore Error dict. An
    unexpected success cancels the started task and raises AssertionError, because a
    target that accepts a call AWS refuses must fail loudly."""
    deadline = time.monotonic() + timeout_s
    error = None
    while True:
        try:
            result = rds.start_export_task(**kwargs)
        except botocore.exceptions.ClientError as exc:
            error = exc.response.get("Error", {})
        else:
            try:
                rds.cancel_export_task(ExportTaskIdentifier=kwargs["ExportTaskIdentifier"])
            except botocore.exceptions.ClientError:
                pass
            raise AssertionError(
                f"expected StartExportTask to be rejected, but it SUCCEEDED and returned {result!r}"
            )
        if time.monotonic() >= deadline:
            return error
        time.sleep(interval_s)


def _cancel_export_task_quietly(rds, export_task_id):
    try:
        rds.cancel_export_task(ExportTaskIdentifier=export_task_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExportTaskNotFound":
            raise


def _list_objects(s3, bucket, prefix):
    keys = []
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        keys.extend(o["Key"] for o in page.get("Contents", []))
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
