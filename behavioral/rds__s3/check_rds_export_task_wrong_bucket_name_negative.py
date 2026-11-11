"""rds-export-task-wrong-bucket-name-negative."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rds-export-task-wrong-bucket-name-negative"
GROUP = "permission-boundary"
SERVICES = ["rds", "s3"]


@tags(
    "axis:rejection",
    "cap:c1",
    "cap:c4",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """StartExportTask to a bucket that does not exist fails at once with InvalidS3BucketFault and the bucket
    stays absent (HeadBucket 404), while the same role and snapshot export to an existing bucket."""
    rds = ctx.client("rds")
    # One teardown window for this run's export cancels.
    teardown = {}
    s3 = ctx.client("s3")

    # a role with a wildcard S3 resource so the only broken variable is the bucket's existence,
    # not an IAM scoping mismatch
    role_arn = _create_wildcard_export_role(ctx)
    kms_key_arn = _grant_kms(ctx, role_arn)
    instance = _create_mysql_instance(ctx)
    snapshot = _create_snapshot(ctx, instance["id"])

    nonexistent_bucket = ctx.unique_name("sim2real-rds-export-missing-")
    bad_task_id = ctx.unique_name("sim2real-export-nobucket-")
    # RDS validates the target bucket synchronously before it ever returns a task, so a
    # nonexistent bucket surfaces as a ClientError on the StartExportTask call itself.
    code, message = _error_code_with_retry(
        lambda: rds.start_export_task(
            ExportTaskIdentifier=bad_task_id,
            SourceArn=snapshot["arn"],
            S3BucketName=nonexistent_bucket,
            IamRoleArn=role_arn,
            KmsKeyId=kms_key_arn,
        ),
        # the role/policy attached moments earlier can transiently surface as one of these
        # before IAM/KMS propagate, which would otherwise mask the persistent
        # InvalidS3BucketFault this check is asserting on.
        retryable_codes=("KMSKeyNotAccessibleFault", "IamRoleMissingPermissions"),
    )
    ctx.on_cleanup(lambda: _best_effort_cancel(rds, bad_task_id, teardown))
    assert code == "InvalidS3BucketFault", f"expected InvalidS3BucketFault targeting a nonexistent bucket, got {code}"
    expected = (
        f"The S3 bucket {nonexistent_bucket} isn't valid. Either it isn't located in the current "
        "AWS Region or it doesn't exist."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # the bucket must genuinely never have come into existence as a side effect of the export attempt
    code2 = _error_code(lambda: s3.head_bucket(Bucket=nonexistent_bucket))
    assert code2 == "404", f"expected the never-created bucket to still be absent, got head_bucket code={code2}"


    # positive control: same role/snapshot, a bucket that actually exists succeeds
    real_bucket = _create_bucket(ctx)
    good_task_id = ctx.unique_name("sim2real-export-realbucket-")
    _start_export_task_with_retry(
        rds,
        ExportTaskIdentifier=good_task_id,
        SourceArn=snapshot["arn"],
        S3BucketName=real_bucket,
        IamRoleArn=role_arn,
        KmsKeyId=kms_key_arn,
    )
    ctx.on_cleanup(lambda: _best_effort_cancel(rds, good_task_id, teardown))
    good_task = _wait_export_task(rds, good_task_id)
    assert good_task["Status"] == "COMPLETE", f"positive control export failed: {good_task.get('FailureCause')}"


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"]
    raise AssertionError("expected the call to fail, but it succeeded")


def _error_code_with_retry(fn, retryable_codes, timeout_s=90.0, interval_s=5.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            raise AssertionError("start_export_task unexpectedly succeeded against a bucket that was never created")
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in retryable_codes and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            return code, err.response["Error"].get("Message", "")


def _start_export_task_with_retry(rds, *, timeout_s=90.0, interval_s=5.0, **kwargs):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return rds.start_export_task(**kwargs)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("IamRoleMissingPermissions", "AccessDenied", "KMSKeyNotAccessibleFault") and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


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
    if ctx.region != "us-east-1":
        # us-east-1 is S3's default region and CreateBucket rejects an explicit
        # LocationConstraint there; every other region requires one.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _cleanup():
        _empty_bucket(s3, name)
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _create_wildcard_export_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-rds-export-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "export.rds.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    statement = {
        "Sid": "ExportPolicyWildcard",
        "Effect": "Allow",
        "Action": ["s3:PutObject*", "s3:ListBucket", "s3:GetObject*", "s3:DeleteObject*", "s3:GetBucketLocation"],
        "Resource": "arn:aws:s3:::*",
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
