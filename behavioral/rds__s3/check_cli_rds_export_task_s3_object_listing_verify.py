"""cli-rds-export-task-s3-object-listing-verify."""

from __future__ import annotations

import json
import secrets
import subprocess
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-rds-export-task-s3-object-listing-verify"
GROUP = "cli-roundtrip"
SERVICES = ["rds", "s3"]


@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """`aws s3 ls --recursive` on the S3Prefix of a completed RDS export task returns the
    parquet table files RDS actually wrote (not merely a synthetic marker object)."""
    require_tools("aws")

    rds = ctx.client("rds")

    bucket = _create_export_bucket(ctx)
    key_id, key_arn = _create_kms_key(ctx)
    role_arn = _create_export_role(ctx, bucket, key_arn, grant_s3=True)
    snap_arn = _provision_seeded_cluster_snapshot(ctx)

    export_id = ctx.unique_name("sim2real-rds-export-")
    s3_prefix = ctx.unique_name("sim2real-rds-prefix-")
    _start_export_task_with_role_propagation_retry(
        rds,
        ExportTaskIdentifier=export_id,
        SourceArn=snap_arn,
        S3BucketName=bucket,
        S3Prefix=s3_prefix,
        IamRoleArn=role_arn,
        KmsKeyId=key_id,
    )
    task = _poll_until(
        lambda: rds.describe_export_tasks(ExportTaskIdentifier=export_id)[
            "ExportTasks"
        ][0],
        lambda t: t["Status"] in ("COMPLETE", "FAILED", "CANCELED"),
        timeout_s=1800.0,
        interval_s=30.0,
        desc=f"export task {export_id} terminal",
    )
    assert task["Status"] == "COMPLETE", (
        f"export task ended in {task['Status']!r}, not COMPLETE"
    )

    proc = _run_shell(
        ctx,
        ["aws", "s3", "ls", f"s3://{bucket}/{s3_prefix}/", "--recursive"],
        timeout_s=30.0,
    )
    lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    assert lines, f"aws s3 ls returned no objects under s3://{bucket}/{s3_prefix}/"

    # RDS writes the exported table data as compressed Parquet files nested under
    # <prefix>/<export_id>/... (see USER_ExportSnapshot.FileNames.html); assert the
    # listing actually reflects that structure, not just an empty marker key.
    assert any(export_id in ln for ln in lines), (
        f"none of the {len(lines)} listed keys contain the export task identifier {export_id!r}"
    )
    assert any(ln.lower().endswith(".parquet") for ln in lines), (
        f"no .parquet table file found among listed keys: {lines[:5]!r}"
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


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0, desc="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{desc} not satisfied within {timeout_s}s (last observed: {last})"
    )


def _create_export_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-rds-export-")
    kwargs: dict[str, Any] = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=name, **kwargs)

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
    ctx.on_cleanup(
        lambda: kms.schedule_key_deletion(KeyId=meta["KeyId"], PendingWindowInDays=7)
    )
    return meta["KeyId"], meta["Arn"]


def _create_export_role(
    ctx, bucket_name: str, kms_key_arn: str, *, grant_s3: bool = True
) -> str:
    iam = ctx.client("iam")
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
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    statements = [
        {
            "Sid": "KmsAccess",
            "Effect": "Allow",
            "Action": [
                "kms:CreateGrant",
                "kms:DescribeKey",
                "kms:Decrypt",
                "kms:GenerateDataKey*",
            ],
            "Resource": kms_key_arn,
        }
    ]
    if grant_s3:
        statements.append(
            {
                "Sid": "S3Access",
                "Effect": "Allow",
                "Action": [
                    "s3:PutObject*",
                    "s3:GetObject*",
                    "s3:ListBucket",
                    "s3:DeleteObject*",
                    "s3:GetBucketLocation",
                ],
                "Resource": [
                    f"arn:aws:s3:::{bucket_name}",
                    f"arn:aws:s3:::{bucket_name}/*",
                ],
            }
        )
    policy_name = ctx.unique_name("sim2real-rds-export-policy-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    )
    return role["Role"]["Arn"]


def _start_export_task_with_role_propagation_retry(
    rds, *, timeout_s: float = 60.0, interval_s: float = 5.0, **kwargs
):
    """RDS validates IamRoleArn synchronously against IAM; a role/policy created moments ago
    may not yet be visible on that read path, so retry the specific rejection with a deadline
    rather than sleeping blind before the call."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return rds.start_export_task(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            message = exc.response.get("Error", {}).get("Message", "")
            propagating = code in ("InvalidParameterValue", "AccessDenied") and (
                "role" in message.lower() or "not authorized" in message.lower()
            )
            if not propagating or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _pick_aurora_mysql_version(ctx) -> str:
    rds = ctx.client("rds")
    versions = rds.describe_db_engine_versions(Engine="aurora-mysql")[
        "DBEngineVersions"
    ]
    candidates = [
        v["EngineVersion"]
        for v in versions
        if v["EngineVersion"].startswith("8.0.mysql_aurora.3.")
    ]
    if not candidates:
        candidates = [v["EngineVersion"] for v in versions]
    return sorted(candidates)[-1]


def _try(fn) -> bool:
    try:
        fn()
        return True
    except Exception:
        return False


def _provision_seeded_cluster_snapshot(ctx) -> str:
    """Create an Aurora MySQL Serverless v2 cluster with the RDS Data API enabled, seed one
    real user table via `rds-data` execute_statement (no native SQL driver or CLI required),
    snapshot the cluster, and return the cluster snapshot ARN -- StartExportTask accepts a DB
    CLUSTER snapshot ARN exactly like a DB instance snapshot ARN."""
    rds = ctx.client("rds")
    rds_data = ctx.client("rds-data")
    secretsmanager = ctx.client("secretsmanager")

    engine_version = _pick_aurora_mysql_version(ctx)
    cluster_id = ctx.unique_name("sim2real-rds-cl-")
    password = "Aa1" + secrets.token_urlsafe(14)
    db_name = "sim2realexp"
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-mysql",
        EngineVersion=engine_version,
        MasterUsername="sim2realadmin",
        MasterUserPassword=password,
        DatabaseName=db_name,
        ServerlessV2ScalingConfiguration={"MinCapacity": 0.5, "MaxCapacity": 2.0},
        EnableHttpEndpoint=True,
        BackupRetentionPeriod=1,
        StorageEncrypted=True,
        Tags=[{"Key": "sim2real", "Value": "rds-s3-behavioral"}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_cluster(
            DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True
        )
    )

    instance_id = ctx.unique_name("sim2real-rds-in-")
    rds.create_db_instance(
        DBInstanceIdentifier=instance_id,
        DBClusterIdentifier=cluster_id,
        Engine="aurora-mysql",
        DBInstanceClass="db.serverless",
        Tags=[{"Key": "sim2real", "Value": "rds-s3-behavioral"}],
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_instance(
            DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True
        )
    )

    _poll_until(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=instance_id)[
            "DBInstances"
        ][0]["DBInstanceStatus"],
        lambda status: status == "available",
        timeout_s=1200.0,
        interval_s=20.0,
        desc=f"aurora instance {instance_id} available",
    )
    cluster_arn = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)[
        "DBClusters"
    ][0]["DBClusterArn"]

    secret_name = ctx.unique_name("sim2real-rds-secret-")
    secret_arn = secretsmanager.create_secret(
        Name=secret_name,
        SecretString=json.dumps({"username": "sim2realadmin", "password": password}),
        Tags=[{"Key": "sim2real", "Value": "rds-s3-behavioral"}],
    )["ARN"]
    ctx.on_cleanup(
        lambda: secretsmanager.delete_secret(
            SecretId=secret_arn, ForceDeleteWithoutRecovery=True
        )
    )

    def _seed():
        rds_data.execute_statement(
            resourceArn=cluster_arn,
            secretArn=secret_arn,
            database=db_name,
            sql="CREATE TABLE IF NOT EXISTS export_rows (id INT PRIMARY KEY, val VARCHAR(50))",
        )
        rds_data.execute_statement(
            resourceArn=cluster_arn,
            secretArn=secret_arn,
            database=db_name,
            sql=(
                "INSERT INTO export_rows (id, val) VALUES (1,'alpha'),(2,'beta'),(3,'gamma') "
                "ON DUPLICATE KEY UPDATE val = VALUES(val)"
            ),
        )

    _poll_until(
        lambda: _try(_seed),
        lambda ok: ok is True,
        timeout_s=180.0,
        interval_s=10.0,
        desc="seed table via rds-data",
    )

    snap_id = ctx.unique_name("sim2real-rds-snap-")
    rds.create_db_cluster_snapshot(
        DBClusterSnapshotIdentifier=snap_id,
        DBClusterIdentifier=cluster_id,
        Tags=[{"Key": "sim2real", "Value": "rds-s3-behavioral"}],
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_cluster_snapshot(DBClusterSnapshotIdentifier=snap_id)
    )
    snap = _poll_until(
        lambda: rds.describe_db_cluster_snapshots(DBClusterSnapshotIdentifier=snap_id)[
            "DBClusterSnapshots"
        ][0],
        lambda s: s["Status"] == "available",
        timeout_s=900.0,
        interval_s=15.0,
        desc=f"cluster snapshot {snap_id} available",
    )
    return snap["DBClusterSnapshotArn"]


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
