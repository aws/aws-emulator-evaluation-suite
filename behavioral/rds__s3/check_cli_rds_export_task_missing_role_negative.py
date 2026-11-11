"""cli-rds-export-task-missing-role-negative."""

from __future__ import annotations

import json
import re
import subprocess
import time
import uuid

from behavioral_harness import tags
from fidelity_tests_runner import require_tools
from botocore.exceptions import ClientError

CHECK = "cli-rds-export-task-missing-role-negative"
GROUP = "cli-snapshot-export"
SERVICES = ["rds", "s3"]


@tags(
    "axis:rejection",
    "cap:c1",
    "cap:c4",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """`aws rds start-export-task` with a nonexistent export role fails with KMSKeyNotAccessibleFault
    and its exact message, creates no task and writes nothing, while the real role's export
    completes and writes objects."""
    require_tools("aws")

    bucket, bucket_arn = _create_export_bucket(ctx)
    key_id, key_arn = _create_kms_key(ctx)
    real_role_arn = _create_export_role(ctx, bucket_arn, key_arn)

    db_instance_id = ctx.unique_name("sim2real-rds-negrole-")
    _create_postgres_instance(ctx, db_instance_id)
    _wait_db_instance_available(ctx, db_instance_id)

    snapshot_id = ctx.unique_name("sim2real-snap-negrole-")
    snapshot_arn = _create_snapshot_and_wait(ctx, db_instance_id, snapshot_id)

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bogus_role_arn = f"arn:aws:iam::{account_id}:role/sim2real-does-not-exist-{uuid.uuid4().hex[:12]}"
    bad_export_task_id = ctx.unique_name("sim2real-export-negrole-")

    proc = _run_shell(
        ctx,
        [
            "aws",
            "--output",
            "json",
            "--no-cli-pager",
            "rds",
            "start-export-task",
            "--export-task-identifier",
            bad_export_task_id,
            "--source-arn",
            snapshot_arn,
            "--s3-bucket-name",
            bucket,
            "--iam-role-arn",
            bogus_role_arn,
            "--kms-key-id",
            key_id,
        ],
        check=False,
    )
    assert proc.returncode != 0, (
        "start-export-task with a nonexistent IAM role must be rejected"
    )
    code = _cli_error_code(proc.stderr)
    message = _cli_error_message(proc.stderr)
    expected = (
        f"The specified KMS key [{key_arn}] does not exist, is not enabled or you do not have "
        "permissions to access it."
    )
    # AWS checks the export role's access to the KMS key before it checks that the role exists,
    # so a nonexistent role surfaces as KMSKeyNotAccessibleFault.
    assert (code, message) == ("KMSKeyNotAccessibleFault", expected), (
        f"expected KMSKeyNotAccessibleFault with message {expected!r}, got {code!r} "
        f"(stderr={proc.stderr[-300:]!r})"
    )

    # (b) the effect is absent: the rejected task was never created, and nothing was ever
    # written under its prefix.
    described = _run_aws(
        ctx,
        "rds",
        "describe-export-tasks",
        "--export-task-identifier",
        bad_export_task_id,
        check=False,
    )
    assert described == {} or described.get("ExportTasks", []) == [], (
        f"rejected export task {bad_export_task_id} should not be describable, got {described!r}"
    )
    listing = _run_aws(
        ctx,
        "s3",
        "ls",
        f"s3://{bucket}/{bad_export_task_id}/",
        "--recursive",
        check=False,
    )
    assert listing == "" or listing == {}, (
        f"rejected export task must write nothing under its S3 prefix, got {listing!r}"
    )

    # (c) positive control, same file: the identical request with the real export role succeeds.
    good_export_task_id = ctx.unique_name("sim2real-export-goodrole-")
    ctx.on_cleanup(lambda: _cancel_export_task_quietly(ctx, good_export_task_id))
    start_resp = _start_export_task_with_retry(
        ctx,
        export_task_id=good_export_task_id,
        source_arn=snapshot_arn,
        bucket=bucket,
        role_arn=real_role_arn,
        key_id=key_id,
    )
    assert start_resp["ExportTaskIdentifier"] == good_export_task_id, (
        f"expected ExportTaskIdentifier {good_export_task_id!r}, got {start_resp!r}"
    )
    assert start_resp["SourceArn"] == snapshot_arn, (
        f"expected SourceArn {snapshot_arn!r}, got {start_resp!r}"
    )
    task = ctx.client("rds").describe_export_tasks(
        ExportTaskIdentifier=good_export_task_id
    )["ExportTasks"][0]
    assert task["Status"] in ("STARTING", "IN_PROGRESS", "COMPLETE"), (
        f"identical call with the real export role must succeed, got status {task['Status']!r}"
    )

    # (d) cross-service terminal read at the CONSUMER: wait for the export to finish, then read S3
    # -- not RDS's own status word -- for the actual delivered objects.
    completed = _wait_export_task_terminal(ctx, good_export_task_id)
    assert completed["Status"] == "COMPLETE", (
        f"positive-control export with a valid role must finish COMPLETE, got "
        f"{completed['Status']!r} ({completed.get('FailureCause')})"
    )
    good_listing = _run_aws(
        ctx,
        "s3",
        "ls",
        f"s3://{bucket}/{good_export_task_id}/",
        "--recursive",
        check=False,
    )
    assert good_listing not in ("", {}), (
        f"a completed export with a valid role must deliver objects under its S3 prefix, "
        f"got {good_listing!r}"
    )


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        command,
        shell=isinstance(command, str),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        cwd=cwd,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"Command failed (rc={result.returncode}):\n  cmd: {command}\n"
            f"  stderr: {result.stderr[-500:]}"
        )
    return result


def _run_aws(ctx, *args: str, timeout_s=30.0, check=True):
    proc = _run_shell(
        ctx,
        ["aws", "--output", "json", "--no-cli-pager", *args],
        timeout_s=timeout_s,
        check=check,
    )
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _cli_error_code(stderr: str):
    m = re.search(r"An error occurred \(([A-Za-z0-9]+)\)", stderr)
    return m.group(1) if m else None


def _cli_error_message(stderr: str):
    m = re.search(r"An error occurred \([A-Za-z0-9]+\) when calling the \w+ operation: (.*)", stderr)
    return m.group(1).strip() if m else None


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_export_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-rds-export-negrole-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket))
    return bucket, f"arn:aws:s3:::{bucket}"


def _delete_bucket(ctx, bucket):
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        objs = page.get("Contents", [])
        if objs:
            failed = s3.delete_objects(
                Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
            ).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _create_kms_key(ctx):
    kms = ctx.client("kms")
    resp = kms.create_key(
        Description="sim2real behavioral rds export missing-role-negative key",
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
    )
    key_id = resp["KeyMetadata"]["KeyId"]
    key_arn = resp["KeyMetadata"]["Arn"]
    ctx.on_cleanup(
        lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    )
    return key_id, key_arn


def _create_export_role(ctx, bucket_arn, key_arn):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-rds-exp-role-negrole-")
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
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust)
    )
    role_arn = role["Role"]["Arn"]
    policy_name = "s3-export-access"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:PutObject*",
                    "s3:GetObject*",
                    "s3:ListBucket",
                    "s3:DeleteObject*",
                    "s3:GetBucketLocation",
                ],
                "Resource": [bucket_arn, f"{bucket_arn}/*"],
            },
            {
                "Effect": "Allow",
                "Action": ["kms:CreateGrant", "kms:DescribeKey"],
                "Resource": key_arn,
            },
        ],
    }
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(policy_doc),
    )

    def _cleanup():
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_postgres_instance(ctx, db_instance_id):
    rds = ctx.client("rds")
    password = f"S2r{uuid.uuid4().hex[:12]}Aa1"
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=db_instance_id,
        Engine="postgres",
        DBInstanceClass="db.t3.micro",
        AllocatedStorage=20,
        MasterUsername="behavadmin",
        MasterUserPassword=password,
        PubliclyAccessible=False,
        BackupRetentionPeriod=0,
        DBSubnetGroupName=subnet_group,
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_instance(
            DBInstanceIdentifier=db_instance_id, SkipFinalSnapshot=True
        )
    )
    return password


def _network_db_subnet_group(ctx, rds):
    """A DB subnet group over the run's shared network, deleted once the instance releases it."""
    name = ctx.unique_name("sim2real-net-dbsg-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_subnet_group(rds, name))
    return name


def _delete_subnet_group(rds, name, *, timeout_s=1200.0):
    """Delete the subnet group, retrying while a deleting instance still holds it; any other
    error, or the deadline, raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            rds.delete_db_subnet_group(DBSubnetGroupName=name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "DBSubnetGroupNotFoundFault":
                return
            if code != "InvalidDBSubnetGroupStateFault" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _wait_db_instance_available(ctx, db_instance_id, timeout_s=1500.0, interval_s=20.0):
    rds = ctx.client("rds")

    def probe():
        return rds.describe_db_instances(DBInstanceIdentifier=db_instance_id)[
            "DBInstances"
        ][0]

    def done(inst):
        status = inst["DBInstanceStatus"]
        if status in ("failed", "incompatible-parameters", "incompatible-network"):
            raise AssertionError(
                f"DB instance {db_instance_id} entered status {status}"
            )
        return status == "available"

    return _poll_until(probe, done, timeout_s=timeout_s, interval_s=interval_s)


def _create_snapshot_and_wait(
    ctx, db_instance_id, snapshot_id, timeout_s=900.0, interval_s=15.0
):
    rds = ctx.client("rds")
    rds.create_db_snapshot(
        DBInstanceIdentifier=db_instance_id, DBSnapshotIdentifier=snapshot_id
    )
    ctx.on_cleanup(lambda: rds.delete_db_snapshot(DBSnapshotIdentifier=snapshot_id))

    def probe():
        return rds.describe_db_snapshots(DBSnapshotIdentifier=snapshot_id)[
            "DBSnapshots"
        ][0]

    def done(snap):
        if snap["Status"] == "failed":
            raise AssertionError(f"snapshot {snapshot_id} failed")
        return snap["Status"] == "available"

    snap = _poll_until(probe, done, timeout_s=timeout_s, interval_s=interval_s)
    return snap["DBSnapshotArn"]


def _start_export_task_with_retry(
    ctx,
    *,
    export_task_id,
    source_arn,
    bucket,
    role_arn,
    key_id,
    timeout_s=90.0,
    interval_s=10.0,
):
    args = [
        "aws",
        "--output",
        "json",
        "--no-cli-pager",
        "rds",
        "start-export-task",
        "--export-task-identifier",
        export_task_id,
        "--source-arn",
        source_arn,
        "--s3-bucket-name",
        bucket,
        "--iam-role-arn",
        role_arn,
        "--kms-key-id",
        key_id,
    ]
    deadline = time.monotonic() + timeout_s
    last_stderr = ""
    while time.monotonic() < deadline:
        proc = _run_shell(ctx, args, check=False)
        if proc.returncode == 0:
            return json.loads(proc.stdout) if proc.stdout.strip() else {}
        last_stderr = proc.stderr
        if (
            "IamRoleNotFound" not in proc.stderr
            and "IamRoleMissingPermissions" not in proc.stderr
        ):
            raise AssertionError(
                f"start-export-task failed unexpectedly: {proc.stderr[-500:]}"
            )
        time.sleep(interval_s)
    raise AssertionError(
        f"start-export-task kept failing on IAM propagation after {timeout_s}s: {last_stderr[-500:]}"
    )


def _cancel_export_task_quietly(ctx, export_task_id):
    rds = ctx.client("rds")
    # A completed task refuses cancel (InvalidExportTaskStateFault); done once it is gone or terminal.
    deadline = time.monotonic() + 600.0
    while True:
        try:
            rds.cancel_export_task(ExportTaskIdentifier=export_task_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ExportTaskNotFound":
                return
            if code != "InvalidExportTaskStateFault":
                raise
        tasks = rds.describe_export_tasks(ExportTaskIdentifier=export_task_id).get("ExportTasks", [])
        if not tasks or tasks[0]["Status"] in ("COMPLETE", "FAILED", "CANCELED"):
            return
        if time.monotonic() >= deadline:
            raise RuntimeError(f"export task {export_task_id} still {tasks[0]['Status']} after 600 s")
        time.sleep(2.0)


def _wait_export_task_terminal(ctx, export_task_id, timeout_s=2700.0, interval_s=20.0):
    rds = ctx.client("rds")
    terminal = ("COMPLETE", "FAILED", "CANCELED")

    def probe():
        return rds.describe_export_tasks(ExportTaskIdentifier=export_task_id)[
            "ExportTasks"
        ][0]

    return _poll_until(
        probe,
        lambda t: t["Status"] in terminal,
        timeout_s=timeout_s,
        interval_s=interval_s,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
