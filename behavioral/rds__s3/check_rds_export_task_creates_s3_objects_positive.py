"""rds-export-task-creates-s3-objects-positive."""
from __future__ import annotations

import json
import secrets
import time

from botocore.exceptions import ClientError

import botocore.exceptions

from behavioral_harness import tags

CHECK = "rds-export-task-creates-s3-objects-positive"
GROUP = "event-propagation"
SERVICES = ["rds", "s3"]

EXPORT_PRINCIPAL = "export.rds.amazonaws.com"
RESOURCE_TAGS = [{"Key": "sim2real", "Value": CHECK}]


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartExportTask on a real RDS snapshot writes exported Parquet objects into
    the target S3 bucket/prefix, and DescribeExportTasks reports the terminal
    COMPLETE state with extraction metadata once the objects have landed."""
    rds = ctx.client("rds")
    s3 = ctx.client("s3")

    bucket = _create_bucket(ctx)
    key_arn = _create_kms_key(ctx)
    snapshot_arn = _provision_seeded_snapshot(ctx)
    role_arn = _create_export_role(ctx, EXPORT_PRINCIPAL, bucket, key_arn, grant_permissions=True)

    task_id = ctx.unique_name("sim2real-export-")
    prefix = "positive"
    _start_export_task_with_retry(
        rds,
        ExportTaskIdentifier=task_id,
        SourceArn=snapshot_arn,
        S3BucketName=bucket,
        IamRoleArn=role_arn,
        KmsKeyId=key_arn,
        S3Prefix=prefix,
    )

    task = _poll_until(
        lambda: rds.describe_export_tasks(ExportTaskIdentifier=task_id)["ExportTasks"][0],
        lambda t: t["Status"] in ("COMPLETE", "FAILED", "CANCELED"),
        timeout_s=1800,
        interval_s=20,
    )
    assert task["Status"] == "COMPLETE", f"export task did not complete: {task}"

    objects = s3.list_objects_v2(Bucket=bucket, Prefix=prefix).get("Contents", [])
    assert len(objects) > 0, "no objects were written to S3 by the export task"
    parquet_objects = [o for o in objects if o["Key"].endswith(".parquet")]
    assert parquet_objects, f"no .parquet objects among exported keys: {[o['Key'] for o in objects]}"
    assert all(o["Size"] > 0 for o in parquet_objects), "exported parquet object(s) are empty"
    assert task.get("TotalExtractedDataInGB") is not None, (
        f"completed export task reported no TotalExtractedDataInGB: {task}"
    )


def _poll_until(probe, predicate, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _best_effort(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "DBClusterNotFoundFault",
            "DBClusterSnapshotNotFoundFault",
            "DBInstanceNotFound",
            "NoSuchBucket",
            "NoSuchEntity",
            "NotFoundException",
            "ResourceNotFoundException",
        ):
            raise


def _try(fn) -> bool:
    try:
        fn()
        return True
    except Exception:
        return False


def _random_password() -> str:
    return "Aa1" + secrets.token_urlsafe(14)


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-rdss3-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _best_effort(lambda: _empty_and_delete_bucket(ctx, name)))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": RESOURCE_TAGS})
    return name


def _empty_and_delete_bucket(ctx, name: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=name):
        keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if keys:
            failed = s3.delete_objects(Bucket=name, Delete={"Objects": keys}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=name)


def _create_kms_key(ctx) -> str:
    kms = ctx.client("kms")
    key = kms.create_key(
        Description="sim2real rds-s3 export test key",
        Tags=[{"TagKey": t["Key"], "TagValue": t["Value"]} for t in RESOURCE_TAGS],
    )["KeyMetadata"]
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: kms.schedule_key_deletion(KeyId=key["KeyId"], PendingWindowInDays=7)
        )
    )
    return key["Arn"]


def _create_export_role(
    ctx, principal: str, bucket_name: str | None, key_arn: str | None, grant_permissions: bool
) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-rdss3-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": principal}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=RESOURCE_TAGS
    )["Role"]
    ctx.on_cleanup(lambda: _best_effort(lambda: iam.delete_role(RoleName=role_name)))

    if grant_permissions and bucket_name and key_arn:
        statements = [
            {
                "Sid": "S3Export",
                "Effect": "Allow",
                "Action": [
                    "s3:PutObject*",
                    "s3:ListBucket",
                    "s3:GetObject*",
                    "s3:DeleteObject*",
                    "s3:GetBucketLocation",
                ],
                "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
            },
            {
                "Sid": "KmsExport",
                "Effect": "Allow",
                "Action": ["kms:CreateGrant", "kms:DescribeKey"],
                "Resource": key_arn,
            },
        ]
        policy_name = f"{role_name}-policy"
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )
        ctx.on_cleanup(
            lambda: _best_effort(
                lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
            )
        )
    return role["Arn"]


_TRANSIENT_EXPORT_START_CODES = (
    "IamRoleMissingPermissions",
    "KMSKeyNotAccessibleFault",
    "InvalidS3BucketFault",
)


def _start_export_task_with_retry(rds, *, timeout_s=180.0, interval_s=10.0, **kwargs):
    """A freshly created IAM role/policy and KMS grant can take a short time to
    propagate, so StartExportTask can transiently answer IamRoleMissingPermissions or
    KMSKeyNotAccessibleFault right after the role or grant is created, even when the
    role's KMS policy is already in place. Retry those specific conditions on a
    bounded deadline; any other error propagates immediately."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return rds.start_export_task(**kwargs)
        except botocore.exceptions.ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in _TRANSIENT_EXPORT_START_CODES:
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _pick_aurora_mysql_version(ctx) -> str:
    """Pick a recent aurora-mysql 3.x engine version (Data API requires 3.02+)."""
    rds = ctx.client("rds")
    versions = rds.describe_db_engine_versions(Engine="aurora-mysql")["DBEngineVersions"]
    candidates = [
        v["EngineVersion"] for v in versions if v["EngineVersion"].startswith("8.0.mysql_aurora.3.")
    ]
    if not candidates:
        candidates = [v["EngineVersion"] for v in versions]
    return sorted(candidates)[-1]


def _provision_seeded_snapshot(ctx) -> str:
    """Create an Aurora MySQL Serverless v2 cluster with the RDS Data API enabled, seed
    one real user table via `rds-data` execute_statement -- no native SQL driver or CLI
    required (this sandbox runtime has neither pymysql nor the mysql CLI) -- snapshot the
    cluster, and return the cluster snapshot ARN. StartExportTask accepts a DB CLUSTER
    snapshot ARN exactly like a DB instance snapshot ARN."""
    rds = ctx.client("rds")
    rds_data = ctx.client("rds-data")
    secretsmanager = ctx.client("secretsmanager")

    engine_version = _pick_aurora_mysql_version(ctx)
    cluster_id = ctx.unique_name("sim2real-rdss3-cl-")
    password = _random_password()
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-mysql",
        EngineVersion=engine_version,
        MasterUsername="dbadmin",
        MasterUserPassword=password,
        DatabaseName="sim2reals3",
        ServerlessV2ScalingConfiguration={"MinCapacity": 0.5, "MaxCapacity": 2.0},
        EnableHttpEndpoint=True,
        BackupRetentionPeriod=1,
        StorageEncrypted=True,
        Tags=RESOURCE_TAGS,
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
        )
    )

    instance_id = ctx.unique_name("sim2real-rdss3-in-")
    rds.create_db_instance(
        DBInstanceIdentifier=instance_id,
        DBClusterIdentifier=cluster_id,
        Engine="aurora-mysql",
        DBInstanceClass="db.serverless",
        Tags=RESOURCE_TAGS,
    )
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: rds.delete_db_instance(DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True)
        )
    )

    _poll_until(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0][
            "DBInstanceStatus"
        ],
        lambda status: status == "available",
        timeout_s=1200,
        interval_s=20,
    )
    cluster_arn = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0][
        "DBClusterArn"
    ]

    secret_name = ctx.unique_name("sim2real-rdss3-secret-")
    secret_arn = secretsmanager.create_secret(
        Name=secret_name,
        SecretString=json.dumps({"username": "dbadmin", "password": password}),
        Tags=RESOURCE_TAGS,
    )["ARN"]
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: secretsmanager.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True)
        )
    )

    def _seed():
        rds_data.execute_statement(
            resourceArn=cluster_arn,
            secretArn=secret_arn,
            database="sim2reals3",
            sql="CREATE TABLE IF NOT EXISTS export_rows (id INT PRIMARY KEY, val VARCHAR(50))",
        )
        rds_data.execute_statement(
            resourceArn=cluster_arn,
            secretArn=secret_arn,
            database="sim2reals3",
            sql=(
                "INSERT INTO export_rows (id, val) VALUES (1,'alpha'),(2,'beta'),(3,'gamma') "
                "ON DUPLICATE KEY UPDATE val = VALUES(val)"
            ),
        )

    _poll_until(lambda: _try(_seed), lambda ok: ok is True, timeout_s=180, interval_s=10)

    snap_id = ctx.unique_name("sim2real-rdss3-snap-")
    rds.create_db_cluster_snapshot(DBClusterSnapshotIdentifier=snap_id, DBClusterIdentifier=cluster_id)
    ctx.on_cleanup(
        lambda: _best_effort(lambda: rds.delete_db_cluster_snapshot(DBClusterSnapshotIdentifier=snap_id))
    )
    snap = _poll_until(
        lambda: rds.describe_db_cluster_snapshots(DBClusterSnapshotIdentifier=snap_id)[
            "DBClusterSnapshots"
        ][0],
        lambda s: s["Status"] == "available",
        timeout_s=900,
        interval_s=15,
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
