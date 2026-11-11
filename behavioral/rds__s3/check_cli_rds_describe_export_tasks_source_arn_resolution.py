"""cli-rds-describe-export-tasks-source-arn-resolution."""

from __future__ import annotations

import json
import subprocess
import time

from botocore.exceptions import ClientError
import uuid

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-rds-describe-export-tasks-source-arn-resolution"
GROUP = "cli-snapshot-export"
SERVICES = ["rds", "s3"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """describe-export-tasks' SourceArn resolves to the exact snapshot ARN used to start the
    export, both in the synchronous start-export-task response and in a fresh
    describe-export-tasks query -- verifying ARN propagation through the CLI workflow."""
    require_tools("aws")

    bucket, bucket_arn = _create_export_bucket(ctx)
    key_id, key_arn = _create_kms_key(ctx)
    role_arn = _create_export_role(ctx, bucket_arn, key_arn)

    db_instance_id = ctx.unique_name("sim2real-rds-arn-")
    _create_postgres_instance(ctx, db_instance_id)
    _wait_db_instance_available(ctx, db_instance_id)

    snapshot_id = ctx.unique_name("sim2real-snap-arn-")
    snapshot_arn = _create_snapshot_and_wait(ctx, db_instance_id, snapshot_id)

    export_task_id = ctx.unique_name("sim2real-export-arn-")
    ctx.on_cleanup(lambda: _cancel_export_task_quietly(ctx, export_task_id))
    start_resp = _start_export_task(
        ctx,
        export_task_id=export_task_id,
        source_arn=snapshot_arn,
        bucket=bucket,
        role_arn=role_arn,
        key_id=key_id,
    )
    # The synchronous StartExportTask response already echoes the resolved SourceArn.
    assert start_resp["SourceArn"] == snapshot_arn, (
        f"start-export-task SourceArn mismatch: expected {snapshot_arn!r}, "
        f"got {start_resp.get('SourceArn')!r}"
    )
    assert start_resp["ExportTaskIdentifier"] == export_task_id, (
        f"start-export-task ExportTaskIdentifier mismatch: expected {export_task_id!r}, "
        f"got {start_resp.get('ExportTaskIdentifier')!r}"
    )

    # A fresh, independent describe-export-tasks call must resolve to the same ARN.
    described = _run_aws(
        ctx, "rds", "describe-export-tasks", "--export-task-identifier", export_task_id
    )
    tasks = described["ExportTasks"]
    assert len(tasks) == 1, (
        f"expected exactly 1 export task, got {len(tasks)}: {tasks!r}"
    )
    assert tasks[0]["SourceArn"] == snapshot_arn, (
        f"describe-export-tasks SourceArn mismatch: expected {snapshot_arn!r}, "
        f"got {tasks[0].get('SourceArn')!r}"
    )
    assert tasks[0]["SourceArn"] == start_resp["SourceArn"], (
        "describe-export-tasks SourceArn diverged from the start-export-task response: "
        f"{tasks[0].get('SourceArn')!r} != {start_resp.get('SourceArn')!r}"
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
    bucket = ctx.unique_name("sim2real-rds-export-arn-")
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
        Description="sim2real behavioral rds export arn-resolution key",
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
    role_name = ctx.unique_name("sim2real-rds-exp-role-arn-")
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
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_instance(
            DBInstanceIdentifier=db_instance_id, SkipFinalSnapshot=True
        )
    )
    return password


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


def _start_export_task(
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
    """rds start-export-task via the CLI, retrying while IAM role propagation is still catching
    up (RDS validates the export role synchronously and a brand-new role can 404 for a short
    window right after CreateRole)."""
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
    """Best-effort cancel so a still-running export doesn't keep writing into the bucket while
    cleanup empties/deletes it. Ignore failures (task may already be terminal)."""
    try:
        ctx.client("rds").cancel_export_task(ExportTaskIdentifier=export_task_id)
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
