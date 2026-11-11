"""cli-rds-create-export-task-verify-s3-sdk."""
from __future__ import annotations

import json
import os
import secrets
import subprocess
import tempfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-rds-create-export-task-verify-s3-sdk"
GROUP = "sdk-cli-interop"
SERVICES = ["rds", "s3"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """`aws rds start-export-task` (CLI) exports a real DB snapshot to S3; the resulting
    objects are discoverable via boto3 s3.list_objects_v2 on the target bucket, and the
    task itself reaches DescribeExportTasks status COMPLETE."""
    require_tools("aws")

    rds = ctx.client("rds")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    kms = ctx.client("kms")

    bucket = _create_bucket(ctx, s3)
    kms_key_arn = _create_kms_key(ctx, kms)
    role_arn = _create_export_role(ctx, iam, [bucket], kms_key_arn)

    db_id = ctx.unique_name("sim2real-rdsexp-")
    _create_db_instance(ctx, rds, db_id)
    snap_id = ctx.unique_name("sim2real-snap-")
    snapshot = _create_snapshot(ctx, rds, db_id, snap_id)
    source_arn = snapshot["DBSnapshotArn"]

    task_id = ctx.unique_name("sim2real-export-")
    _start_export_task_with_retry(ctx, task_id, source_arn, bucket, role_arn, kms_key_arn)

    task = _wait_until(
        lambda: _describe_export_task(ctx, task_id),
        lambda t: t["Status"] in ("COMPLETE", "FAILED", "CANCELED"),
        timeout_s=1200,
        interval_s=15,
        desc=f"export task {task_id} reaching a terminal status",
    )
    assert task["Status"] == "COMPLETE", f"export task did not complete: {task}"

    listing = s3.list_objects_v2(Bucket=bucket, Prefix=task_id)
    contents = listing.get("Contents", [])
    keys = [obj["Key"] for obj in contents]
    assert keys, f"no S3 objects found under prefix {task_id!r} in bucket {bucket}"
    manifest_key = f"{task_id}/export_info_{task_id}.json"
    assert manifest_key in keys, f"expected RDS export manifest {manifest_key!r} not found among: {keys!r}"
    manifest = json.loads(s3.get_object(Bucket=bucket, Key=manifest_key)["Body"].read())
    assert manifest.get("exportTaskIdentifier") == task_id, (
        f"export manifest exportTaskIdentifier does not match {task_id!r}; full manifest={manifest!r}"
    )
    assert manifest.get("status") == "COMPLETE", f"export manifest status not COMPLETE: {manifest!r}"
    zero_size = [obj["Key"] for obj in contents if obj["Size"] <= 0]
    assert not zero_size, f"exported object(s) with non-positive size (empty marker, not real data): {zero_size!r}"


# ===== CLI helpers =====

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


def _run_script(ctx, script: str, *, timeout_s=120.0, check=True, env_extra=None):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
        f.write("#!/bin/bash\nset -euo pipefail\n")
        f.write(script)
        script_path = f.name
    try:
        os.chmod(script_path, 0o755)
        return _run_shell(ctx, ["bash", script_path], timeout_s=timeout_s, check=check, env_extra=env_extra)
    finally:
        os.unlink(script_path)


def _run_aws(ctx, *args: str, timeout_s=30.0, check=True):
    proc = _run_shell(ctx, ["aws", "--output", "json", "--no-cli-pager", *args], timeout_s=timeout_s, check=check)
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


# ===== resource helpers =====

def _wait_until(probe, predicate, *, timeout_s, interval_s=15.0, desc="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {desc}; last observed={last!r}")


def _db_password() -> str:
    raw = secrets.token_urlsafe(14).replace("-", "A").replace("_", "B")
    return "S2rExp1" + raw[:12]


def _create_bucket(ctx, s3):
    name = ctx.unique_name("sim2real-rds-export-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))
    return name


def _empty_and_delete_bucket(s3, name):
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=name):
            objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objs:
                failed = s3.delete_objects(Bucket=name, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_kms_key(ctx, kms):
    key = kms.create_key(
        Description="sim2real rds export test key",
        Tags=[{"TagKey": "sim2real", "TagValue": "rds-s3-behavioral"}],
    )["KeyMetadata"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key["KeyId"], PendingWindowInDays=7))
    return key["Arn"]


def _create_export_role(ctx, iam, bucket_names, kms_key_arn):
    role_name = ctx.unique_name("sim2real-rds-export-role-")
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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "rds-s3-behavioral"}],
    )["Role"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    resources = []
    for b in bucket_names:
        resources.append(f"arn:aws:s3:::{b}")
        resources.append(f"arn:aws:s3:::{b}/*")
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:PutObject*",
                    "s3:GetObject*",
                    "s3:ListBucket",
                    "s3:GetBucketLocation",
                    "s3:DeleteObject*",
                    "s3:AbortMultipartUpload",
                ],
                "Resource": resources,
            },
            {
                "Effect": "Allow",
                "Action": ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey*", "kms:DescribeKey"],
                "Resource": kms_key_arn,
            },
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="export-s3-kms", PolicyDocument=json.dumps(policy))
    return role["Arn"]


def _delete_role(iam, role_name):
    try:
        for pol in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_db_instance(ctx, rds, db_id):
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=db_id,
        Engine="postgres",
        DBInstanceClass="db.t3.micro",
        AllocatedStorage=20,
        MasterUsername="s2radmin",
        MasterUserPassword=_db_password(),
        PubliclyAccessible=False,
        StorageType="gp2",
        BackupRetentionPeriod=1,
        Tags=[{"Key": "sim2real", "Value": "rds-s3-behavioral"}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_db_instance(rds, db_id))
    return _wait_until(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0],
        lambda inst: inst["DBInstanceStatus"] == "available",
        timeout_s=1200,
        interval_s=20,
        desc=f"db instance {db_id} available",
    )


def _delete_db_instance(rds, db_id):
    try:
        rds.delete_db_instance(DBInstanceIdentifier=db_id, SkipFinalSnapshot=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBInstanceNotFound":
            raise
        return
    # Bounded to fit the suite's cleanup budget together with the other teardowns.
    rds.get_waiter("db_instance_deleted").wait(
        DBInstanceIdentifier=db_id, WaiterConfig={"Delay": 2, "MaxAttempts": 600}
    )


def _create_snapshot(ctx, rds, db_id, snap_id):
    rds.create_db_snapshot(
        DBSnapshotIdentifier=snap_id,
        DBInstanceIdentifier=db_id,
        Tags=[{"Key": "sim2real", "Value": "rds-s3-behavioral"}],
    )
    ctx.on_cleanup(lambda: _delete_snapshot(rds, snap_id))
    return _wait_until(
        lambda: rds.describe_db_snapshots(DBSnapshotIdentifier=snap_id)["DBSnapshots"][0],
        lambda s: s["Status"] == "available",
        timeout_s=900,
        interval_s=15,
        desc=f"snapshot {snap_id} available",
    )


def _delete_snapshot(rds, snap_id):
    try:
        rds.delete_db_snapshot(DBSnapshotIdentifier=snap_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBSnapshotNotFound":
            raise


def _describe_export_task(ctx, task_id):
    out = _run_aws(ctx, "rds", "describe-export-tasks", "--export-task-identifier", task_id)
    tasks = out.get("ExportTasks", [])
    if not tasks:
        raise AssertionError(f"export task {task_id} not found via describe-export-tasks")
    return tasks[0]


def _start_export_task_with_retry(ctx, task_id, source_arn, bucket, role_arn, kms_key_arn, attempts=8, delay_s=15):
    """IAM role/policy propagation is eventually consistent; retry the actual CLI call
    (a real observable condition: does start-export-task succeed yet) rather than sleeping
    a fixed duration."""
    last_err = None
    for _ in range(attempts):
        proc = _run_shell(
            ctx,
            [
                "aws", "--output", "json", "--no-cli-pager", "rds", "start-export-task",
                "--export-task-identifier", task_id,
                "--source-arn", source_arn,
                "--s3-bucket-name", bucket,
                "--iam-role-arn", role_arn,
                "--kms-key-id", kms_key_arn,
            ],
            check=False,
        )
        if proc.returncode == 0:
            return json.loads(proc.stdout) if proc.stdout.strip() else {}
        last_err = proc.stderr
        time.sleep(delay_s)
    raise AssertionError(f"start-export-task failed after {attempts} retries: {last_err}")


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
