"""rds-export-task-s3-bucket-policy-deny-negative."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rds-export-task-s3-bucket-policy-deny-negative"
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
    """With a bucket-policy Deny of the export role's s3:PutObject*, StartExportTask fails at once with
    IamRoleMissingPermissions naming s3:PutObject and writes nothing, even though the role's own policy
    allows it; with the Deny removed, the same role's export completes and writes objects."""
    rds = ctx.client("rds")
    # One teardown window for this run's export cancels.
    teardown = {}
    s3 = ctx.client("s3")

    bucket = _create_bucket(ctx)
    role_arn = _create_export_role(ctx, bucket)
    kms_key_arn = _grant_kms(ctx, role_arn)
    instance = _create_mysql_instance(ctx)
    snapshot = _create_snapshot(ctx, instance["id"])

    # break exactly one thing: an explicit bucket-policy Deny for the export role's PutObject
    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyExportRole",
                "Effect": "Deny",
                "Principal": {"AWS": role_arn},
                "Action": "s3:PutObject*",
                "Resource": f"arn:aws:s3:::{bucket}/*",
            }
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(deny_policy))

    denied_task_id = ctx.unique_name("sim2real-export-denied-")
    # RDS validates the role's effective S3 access (IAM + bucket policy) synchronously before it
    # ever returns a task, so the bucket-policy Deny surfaces as a ClientError on the
    # StartExportTask call itself, not an async FAILED.
    code, message = _error_code(
        lambda: rds.start_export_task(
            ExportTaskIdentifier=denied_task_id,
            SourceArn=snapshot["arn"],
            S3BucketName=bucket,
            IamRoleArn=role_arn,
            KmsKeyId=kms_key_arn,
            S3Prefix="denied",
        )
    )
    ctx.on_cleanup(lambda: _best_effort_cancel(rds, denied_task_id, teardown))
    assert code == "IamRoleMissingPermissions", f"expected IamRoleMissingPermissions with a bucket policy Deny in place, got {code}"
    expected = f"The IAM role {role_arn} isn't authorized to call s3:PutObject on the S3 bucket {bucket}."
    assert message == expected, f"IamRoleMissingPermissions message {message!r} != {expected!r}"

    denied_objects = s3.list_objects_v2(Bucket=bucket, Prefix="denied/")
    assert "Contents" not in denied_objects, f"export delivered objects despite the bucket-policy Deny: {denied_objects.get('Contents')}"

    # positive control: remove the deny, same role/bucket/snapshot succeeds
    s3.delete_bucket_policy(Bucket=bucket)
    allowed_task_id = ctx.unique_name("sim2real-export-allowed-")
    rds.start_export_task(
        ExportTaskIdentifier=allowed_task_id,
        SourceArn=snapshot["arn"],
        S3BucketName=bucket,
        IamRoleArn=role_arn,
        KmsKeyId=kms_key_arn,
        S3Prefix="allowed",
    )
    ctx.on_cleanup(lambda: _best_effort_cancel(rds, allowed_task_id, teardown))
    allowed_task = _wait_export_task(rds, allowed_task_id)
    assert allowed_task["Status"] == "COMPLETE", f"positive control export failed: {allowed_task.get('FailureCause')}"

    # terminal read at the consumer (S3), not just the producer's (RDS) own status field
    allowed_objects = s3.list_objects_v2(Bucket=bucket, Prefix="allowed/")
    assert "Contents" in allowed_objects, "positive control reported COMPLETE but wrote no objects to S3"


def _error_code(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError("expected the call to fail, but it succeeded")


def _poll_until(probe, predicate, *, timeout_s=1200.0, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


_EXPORT_DONE = {"COMPLETE", "CANCELED", "CANCELING", "FAILED"}


_FINISHED = {"COMPLETE", "CANCELED", "FAILED", None}


def _best_effort_cancel(rds, task_id, teardown):
    """Cancel the export unless it is absent or already finished (CancelExportTask answers
    InvalidExportTaskStateFault "The export ... can't be canceled." for a finished one), then wait
    every 2 s until it is finished, so no late write races the bucket teardown. The cancels share
    one per-run 240 s window; with the subnet-group teardown's 1500 s it fits the 1800 s budget."""
    if "deadline" not in teardown:
        teardown["deadline"] = time.monotonic() + 240.0
    deadline = teardown["deadline"]
    if _export_status(rds, task_id) in _FINISHED:
        return
    try:
        rds.cancel_export_task(ExportTaskIdentifier=task_id)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "ExportTaskNotFound":
            return
        if code != "InvalidExportTaskStateFault" or _export_status(rds, task_id) not in _EXPORT_DONE:
            raise
    status = _export_status(rds, task_id)
    while status not in _FINISHED:
        if time.monotonic() >= deadline:
            raise TimeoutError(f"export {task_id} still {status} at the teardown deadline")
        time.sleep(2)
        status = _export_status(rds, task_id)


def _export_status(rds, task_id):
    """The export task's Status, or None when DescribeExportTasks does not list it."""
    try:
        tasks = rds.describe_export_tasks(ExportTaskIdentifier=task_id)["ExportTasks"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExportTaskNotFound":
            raise
        return None
    return tasks[0]["Status"] if tasks else None


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
    if ctx.region != "us-east-1":  # S3 rejects an explicit LocationConstraint for us-east-1 itself
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _cleanup():
        try:
            s3.delete_bucket_policy(Bucket=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise
        _empty_bucket(s3, name)
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _create_export_role(ctx, bucket_name):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-rds-export-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "export.rds.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    statement = {
        "Sid": "ExportPolicy",
        "Effect": "Allow",
        "Action": ["s3:PutObject*", "s3:ListBucket", "s3:GetObject*", "s3:DeleteObject*", "s3:GetBucketLocation"],
        "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
    }
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
