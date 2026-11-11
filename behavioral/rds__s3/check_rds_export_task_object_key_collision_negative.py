"""rds-export-task-object-key-collision-negative."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rds-export-task-object-key-collision-negative"
GROUP = "permission-boundary"
SERVICES = ["rds", "s3"]


@tags(
    "axis:rejection",
    "cap:c1",
    "cap:c4",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """StartExportTask reusing the identifier of a running export task fails with ExportTaskAlreadyExists and
    leaves the one task record and its prefix unchanged, while a new identifier is accepted and listed."""
    rds = ctx.client("rds")
    # One teardown window for this run's export cancels.
    teardown = {}

    bucket = _create_bucket(ctx)
    role_arn = _create_export_role(ctx, bucket)
    kms_key_arn = _grant_kms(ctx, role_arn)
    instance = _create_mysql_instance(ctx)
    snapshot = _create_snapshot(ctx, instance["id"])

    task_id = ctx.unique_name("sim2real-export-dup-")
    _start_export_task_with_retry(
        rds,
        task_id=task_id,
        source_arn=snapshot["arn"],
        bucket=bucket,
        role_arn=role_arn,
        kms_key_arn=kms_key_arn,
        s3_prefix="first-writer",
    )
    ctx.on_cleanup(lambda: _best_effort_cancel(rds, task_id, teardown))

    # break exactly one thing: start a second task re-using the identifier (and prefix) of the
    # one that is already running - this is rejected synchronously
    code = _error_code(
        lambda: rds.start_export_task(
            ExportTaskIdentifier=task_id,
            SourceArn=snapshot["arn"],
            S3BucketName=bucket,
            IamRoleArn=role_arn,
            KmsKeyId=kms_key_arn,
            S3Prefix="first-writer",
        )
    )
    assert code == "ExportTaskAlreadyExists", f"expected ExportTaskAlreadyExists reusing a live identifier, got {code}"

    # the effect is absent: there is still exactly one export task under this identifier, and its
    # own in-flight status/prefix were left untouched by the rejected duplicate call
    tasks = rds.describe_export_tasks(ExportTaskIdentifier=task_id)["ExportTasks"]
    assert len(tasks) == 1, f"the rejected duplicate call must not have created a second task record: {tasks}"
    assert tasks[0]["S3Prefix"] == "first-writer"
    assert tasks[0]["Status"] in {"STARTING", "IN_PROGRESS", "COMPLETE"}

    # a snapshot only allows one in-flight export at a time, so the first-writer task must reach
    # a terminal state before a genuinely-new identifier against the same snapshot is accepted
    first_task = _wait_export_task(rds, task_id)
    assert first_task["Status"] == "COMPLETE", f"first-writer export failed: {first_task.get('FailureCause')}"

    # positive control: a genuinely new identifier is accepted without error. the
    # snapshot's own per-snapshot export-exclusivity lock does not always clear the instant
    # describe_export_tasks reports the prior task COMPLETE - it can still reject a fresh
    # identifier over two minutes later - so the call is retried while it reports the same
    # in-progress rejection.
    other_task_id = ctx.unique_name("sim2real-export-second-")
    response = _start_export_task_with_retry(
        rds,
        task_id=other_task_id,
        source_arn=snapshot["arn"],
        bucket=bucket,
        role_arn=role_arn,
        kms_key_arn=kms_key_arn,
        s3_prefix="second-writer",
        retry_on={"ExportTaskAlreadyExists"},
        attempts=30,
        delay_s=30,
    )
    ctx.on_cleanup(lambda: _best_effort_cancel(rds, other_task_id, teardown))
    assert response["ExportTaskIdentifier"] == other_task_id
    assert response["Status"] in {"STARTING", "IN_PROGRESS"}

    # terminal read is independent of the mutating call: the new task is visible, under its own
    # identifier and prefix, via describe_export_tasks - not just echoed back by start_export_task
    second_tasks = rds.describe_export_tasks(ExportTaskIdentifier=other_task_id)["ExportTasks"]
    assert (
        len(second_tasks) == 1 and second_tasks[0]["S3Prefix"] == "second-writer"
    ), f"expected the second-writer task independently visible via describe_export_tasks: {second_tasks}"


def _start_export_task_with_retry(
    rds, *, task_id, source_arn, bucket, role_arn, kms_key_arn, s3_prefix, retry_on=None, attempts=8, delay_s=15
):
    """IAM role/KMS-grant propagation is eventually consistent, and immediately after the prior
    task reaches COMPLETE the snapshot's export-exclusivity lock can still momentarily read as
    held; retry the start_export_task call itself. `retry_on=None` retries on any ClientError (propagation); a
    non-None set narrows to the specific error codes worth waiting out."""
    from botocore.exceptions import ClientError

    last_err = None
    for _ in range(attempts):
        try:
            return rds.start_export_task(
                ExportTaskIdentifier=task_id,
                SourceArn=source_arn,
                S3BucketName=bucket,
                IamRoleArn=role_arn,
                KmsKeyId=kms_key_arn,
                S3Prefix=s3_prefix,
            )
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if retry_on is not None and code not in retry_on:
                raise
            last_err = err
            time.sleep(delay_s)
    raise AssertionError(f"start_export_task for {task_id!r} kept failing after {attempts} retries: {last_err}")


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"]
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


def _wait_export_task(rds, task_id, timeout_s=2700.0, interval_s=30.0):
    terminal = {"COMPLETE", "FAILED", "CANCELED"}
    return _poll_until(
        lambda: rds.describe_export_tasks(ExportTaskIdentifier=task_id)["ExportTasks"][0],
        lambda t: t["Status"] in terminal,
        timeout_s=timeout_s,
        interval_s=interval_s,
    )


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
        # S3's CreateBucket rejects an explicit LocationConstraint for us-east-1.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _cleanup():
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
