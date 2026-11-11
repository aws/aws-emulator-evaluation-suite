"""rds-export-task-missing-iam-role-negative."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rds-export-task-missing-iam-role-negative"
GROUP = "permission-boundary"
SERVICES = ["rds", "s3"]


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
    """Export fails (no objects delivered) when the supplied IAM role lacks S3 write permission."""
    rds = ctx.client("rds")
    s3 = ctx.client("s3")

    bucket = _create_bucket(ctx)
    good_role_arn = _create_export_role(ctx, bucket, grant_s3=True)
    _grant_kms(ctx, good_role_arn)
    bad_role_arn = _create_export_role(ctx, bucket, grant_s3=False)
    kms_key_arn = _grant_kms(ctx, bad_role_arn)

    instance = _create_mysql_instance(ctx)
    snapshot = _create_snapshot(ctx, instance["id"])

    # break exactly one thing: the export role has no s3:PutObject* permission on the bucket.
    # RDS validates the role's S3 access synchronously before it ever returns a task, so the
    # rejection surfaces as a ClientError on the StartExportTask call itself, not an async FAILED.
    # The KMS grant on this same role is fresh (see _grant_kms), so a transient KMS-propagation
    # error is retried; IamRoleMissingPermissions itself is the expected terminal answer and is
    # never retried here.
    bad_task_id = ctx.unique_name("sim2real-export-bad-")
    error = _client_error(
        lambda: _retry_transient(
            lambda: rds.start_export_task(
                ExportTaskIdentifier=bad_task_id,
                SourceArn=snapshot["arn"],
                S3BucketName=bucket,
                IamRoleArn=bad_role_arn,
                KmsKeyId=kms_key_arn,
                S3Prefix="bad-role",
            ),
            transient_codes={"KMSKeyNotAccessibleFault"},
        )
    )
    ctx.on_cleanup(lambda: _best_effort_cancel(rds, bad_task_id))
    assert error.get("Code") == "IamRoleMissingPermissions", (
        f"expected IamRoleMissingPermissions with a role lacking S3 access, got {error}"
    )
    # RDS probes s3:GetBucketLocation first, and this role holds no S3 grant at all.
    expected_message = (
        f"The IAM role {bad_role_arn} isn't authorized to call s3:GetBucketLocation "
        f"on the S3 bucket {bucket}."
    )
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    bad_objects = s3.list_objects_v2(Bucket=bucket, Prefix="bad-role/")
    assert "Contents" not in bad_objects, f"role without S3 permission still delivered objects: {bad_objects.get('Contents')}"

    # positive control in the same file: the properly-permissioned role, same bucket/snapshot,
    # succeeds. Both its S3 grant and its KMS grant are fresh, so IamRoleMissingPermissions and
    # KMSKeyNotAccessibleFault are the two propagation-lag shapes retried before treating either
    # as a real rejection.
    good_task_id = ctx.unique_name("sim2real-export-good-")
    _retry_transient(
        lambda: rds.start_export_task(
            ExportTaskIdentifier=good_task_id,
            SourceArn=snapshot["arn"],
            S3BucketName=bucket,
            IamRoleArn=good_role_arn,
            KmsKeyId=kms_key_arn,
            S3Prefix="good-role",
        ),
        transient_codes={"IamRoleMissingPermissions", "KMSKeyNotAccessibleFault"},
    )
    ctx.on_cleanup(lambda: _best_effort_cancel(rds, good_task_id))
    good_task = _wait_export_task(rds, good_task_id)
    assert good_task["Status"] == "COMPLETE", f"positive control export failed: {good_task.get('FailureCause')}"

    # terminal read at the consumer: RDS's own COMPLETE status is the producer's opinion,
    # not proof anything landed. Confirm delivery independently at S3.
    good_objects = s3.list_objects_v2(Bucket=bucket, Prefix="good-role/").get("Contents", [])
    assert good_objects, "positive control reported COMPLETE but delivered no objects to s3 under good-role/"


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises AssertionError:
    a target that accepts a call AWS refuses must fail loudly, not read as a code
    mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _retry_transient(fn, transient_codes, *, timeout_s=90.0, interval_s=10.0):
    """Bounded retry for the specific IAM/KMS-propagation error codes in *transient_codes*.

    Success, or any error not in *transient_codes*, returns/raises immediately -- this exists to
    absorb genuine eventual-consistency lag on a just-attached grant, not to soften a real answer.
    Raises the last ClientError once *timeout_s* is exceeded.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as err:
            if err.response["Error"]["Code"] not in transient_codes or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _poll_until(probe, predicate, *, timeout_s=1200.0, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _best_effort_cancel(rds, task_id):
    try:
        rds.cancel_export_task(ExportTaskIdentifier=task_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExportTaskNotFound":
            raise


def _empty_bucket(s3, name):
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=name):
        objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if objs:
            failed = s3.delete_objects(Bucket=name, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-rds-export-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _cleanup():
        _empty_bucket(s3, name)
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _create_export_role(ctx, bucket_name, grant_s3):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-rds-export-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "export.rds.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    if grant_s3:
        statement = {
            "Sid": "ExportPolicy",
            "Effect": "Allow",
            "Action": ["s3:PutObject*", "s3:ListBucket", "s3:GetObject*", "s3:DeleteObject*", "s3:GetBucketLocation"],
            "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
        }
    else:
        # the role is real and assumable, but is granted no permission whatsoever on S3
        statement = {"Sid": "NoS3Access", "Effect": "Allow", "Action": ["logs:CreateLogGroup"], "Resource": "*"}
    policy_name = f"{role_name}-policy"
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [statement]})
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _grant_kms(ctx, role_arn):
    kms = ctx.client("kms")
    key = kms.create_key(Description="sim2real rds export behavioral test key", KeyUsage="ENCRYPT_DECRYPT")["KeyMetadata"]
    key_id = key["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    iam = ctx.client("iam")
    role_name = role_arn.rsplit("/", 1)[-1]
    policy_name = f"{role_name}-kms"
    statement = {
        "Sid": "AllowExportKms",
        "Effect": "Allow",
        "Action": ["kms:CreateGrant", "kms:DescribeKey", "kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey"],
        "Resource": key["Arn"],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [statement]})
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return key["Arn"]


def _create_mysql_instance(ctx):
    rds = ctx.client("rds")
    instance_id = ctx.unique_name("sim2real-rds-mysql-")
    password = f"Sim2Real{uuid.uuid4().hex[:12]}!"
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=instance_id,
        Engine="mysql",
        DBInstanceClass="db.t3.micro",
        AllocatedStorage=20,
        MasterUsername="sim2real",
        MasterUserPassword=password,
        BackupRetentionPeriod=1,
        Tags=[{"Key": "sim2real", "Value": "rds-s3-behavioral"}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: rds.delete_db_instance(DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True))
    inst = _poll_until(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0],
        lambda i: i["DBInstanceStatus"] == "available",
        timeout_s=1200,
        interval_s=20,
    )
    return {"id": instance_id, "arn": inst["DBInstanceArn"]}


def _create_snapshot(ctx, instance_id):
    rds = ctx.client("rds")
    snap_id = ctx.unique_name("sim2real-rds-snap-")
    rds.create_db_snapshot(DBSnapshotIdentifier=snap_id, DBInstanceIdentifier=instance_id)
    ctx.on_cleanup(lambda: rds.delete_db_snapshot(DBSnapshotIdentifier=snap_id))
    snap = _poll_until(
        lambda: rds.describe_db_snapshots(DBSnapshotIdentifier=snap_id)["DBSnapshots"][0],
        lambda s: s["Status"] == "available",
        timeout_s=1200,
        interval_s=20,
    )
    return {"id": snap_id, "arn": snap["DBSnapshotArn"]}


def _wait_export_task(rds, task_id, timeout_s=2700.0, interval_s=30.0):
    terminal = {"COMPLETE", "FAILED", "CANCELED"}
    return _poll_until(
        lambda: rds.describe_export_tasks(ExportTaskIdentifier=task_id)["ExportTasks"][0],
        lambda t: t["Status"] in terminal,
        timeout_s=timeout_s,
        interval_s=interval_s,
    )


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
