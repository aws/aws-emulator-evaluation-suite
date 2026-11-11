"""cli-rds-describe-export-tasks-status-poll."""
from __future__ import annotations

import json
import subprocess
import time

from botocore.exceptions import ClientError
from typing import Any

import botocore.exceptions

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-rds-describe-export-tasks-status-poll"
GROUP = "cli-workflow"
SERVICES = ["rds", "s3"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """CLI-polled `aws rds describe-export-tasks` Status only reaches COMPLETE once the
    exported objects are actually observable in the destination S3 bucket, and is NOT
    COMPLETE immediately after the task starts."""
    require_tools("aws")

    rds = ctx.client("rds")
    s3 = ctx.client("s3")

    bucket = _create_export_bucket(ctx)
    key_id, key_arn = _create_kms_key(ctx)
    role_arn = _create_export_role(ctx, bucket, key_arn, grant_s3=True)
    db_id = _create_source_db_instance(ctx)
    snap_id, snap_arn = _create_snapshot(ctx, db_id)

    export_id = ctx.unique_name("sim2real-rds-export-")
    _start_export_with_retry(ctx, export_id, snap_arn, bucket, role_arn, key_id)

    # Immediately after starting, the CLI must NOT already report COMPLETE: an export is a
    # multi-minute state transition.
    initial = _run_aws(ctx, "rds", "describe-export-tasks", "--export-task-identifier", export_id)
    initial_status = initial["ExportTasks"][0]["Status"]
    assert initial_status != "COMPLETE", (
        f"export task {export_id} reported COMPLETE immediately after start-export-task"
    )

    def _cli_status() -> str:
        out = _run_aws(ctx, "rds", "describe-export-tasks", "--export-task-identifier", export_id)
        return out["ExportTasks"][0]["Status"]

    final_status = _poll_until(
        _cli_status,
        lambda status: status in ("COMPLETE", "FAILED", "CANCELED"),
        timeout_s=1800.0, interval_s=30.0, desc=f"CLI-observed export task {export_id} terminal",
    )
    assert final_status == "COMPLETE", f"export task ended in {final_status!r} via CLI polling"

    # The instant the CLI observes COMPLETE, the S3 objects must already be present.
    listing = s3.list_objects_v2(Bucket=bucket, Prefix=f"{export_id}/")
    assert listing.get("KeyCount", 0) > 0, (
        f"CLI reported export task {export_id} COMPLETE but s3://{bucket}/{export_id}/ is empty"
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
        ["aws", "--output", "json", *args],
        timeout_s=timeout_s,
        check=check,
    )
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _start_export_with_retry(ctx, export_id, snap_arn, bucket, role_arn, key_id):
    """StartExportTask can transiently fail with IamRoleMissingPermissions right after the
    role/policy was created, due to IAM eventual consistency. Retry that specific condition
    only; any other error propagates immediately."""
    rds = ctx.client("rds")
    deadline = time.monotonic() + 120.0
    while True:
        try:
            rds.start_export_task(
                ExportTaskIdentifier=export_id,
                SourceArn=snap_arn,
                S3BucketName=bucket,
                IamRoleArn=role_arn,
                KmsKeyId=key_id,
            )
            return
        except botocore.exceptions.ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "IamRoleMissingPermissions" and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0, desc="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{desc} not satisfied within {timeout_s}s (last observed: {last})")


def _create_export_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-rds-export-")
    kwargs: dict[str, Any] = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=name, **kwargs)
    s3.put_bucket_tagging(
        Bucket=name,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": "rds-s3-behavioral"}]},
    )

    def _cleanup():
        resp = s3.list_objects_v2(Bucket=name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _create_kms_key(ctx) -> tuple[str, str]:
    kms = ctx.client("kms")
    meta = kms.create_key(
        Description=ctx.unique_name("sim2real-rds-export-key-"),
        Tags=[{"TagKey": "sim2real", "TagValue": "rds-s3-behavioral"}],
    )["KeyMetadata"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=meta["KeyId"], PendingWindowInDays=7))
    return meta["KeyId"], meta["Arn"]


def _create_export_role(ctx, bucket_name: str, kms_key_arn: str, *, grant_s3: bool = True) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-rds-export-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "export.rds.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "rds-s3-behavioral"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    statements = [{
        "Sid": "KmsAccess",
        "Effect": "Allow",
        "Action": ["kms:CreateGrant", "kms:DescribeKey", "kms:Decrypt", "kms:GenerateDataKey*"],
        "Resource": kms_key_arn,
    }]
    if grant_s3:
        statements.append({
            "Sid": "S3Access",
            "Effect": "Allow",
            "Action": ["s3:PutObject*", "s3:GetObject*", "s3:ListBucket", "s3:DeleteObject*", "s3:GetBucketLocation"],
            "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
        })
    policy_name = ctx.unique_name("sim2real-rds-export-policy-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role["Role"]["Arn"]


def _create_source_db_instance(ctx) -> str:
    rds = ctx.client("rds")
    db_id = ctx.unique_name("sim2real-rds-src-")
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=db_id,
        Engine="mysql",
        DBInstanceClass="db.t3.micro",
        AllocatedStorage=20,
        StorageType="gp2",
        MasterUsername="sim2realadmin",
        MasterUserPassword="Sim2RealPwd1!",
        PubliclyAccessible=False,
        BackupRetentionPeriod=1,
        Tags=[{"Key": "sim2real", "Value": "rds-s3-behavioral"}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: rds.delete_db_instance(DBInstanceIdentifier=db_id, SkipFinalSnapshot=True))
    _poll_until(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0]["DBInstanceStatus"],
        lambda status: status == "available",
        timeout_s=1800.0, interval_s=30.0, desc=f"db instance {db_id} available",
    )
    return db_id


def _create_snapshot(ctx, db_id: str) -> tuple[str, str]:
    rds = ctx.client("rds")
    snap_id = ctx.unique_name("sim2real-rds-snap-")
    rds.create_db_snapshot(
        DBSnapshotIdentifier=snap_id,
        DBInstanceIdentifier=db_id,
        Tags=[{"Key": "sim2real", "Value": "rds-s3-behavioral"}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_snapshot(DBSnapshotIdentifier=snap_id))
    snap = _poll_until(
        lambda: rds.describe_db_snapshots(DBSnapshotIdentifier=snap_id)["DBSnapshots"][0],
        lambda s: s["Status"] == "available",
        timeout_s=1200.0, interval_s=20.0, desc=f"snapshot {snap_id} available",
    )
    return snap_id, snap["DBSnapshotArn"]


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
