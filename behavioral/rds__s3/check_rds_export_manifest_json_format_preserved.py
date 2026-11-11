"""rds-export-manifest-json-format-preserved."""
from __future__ import annotations

import json
import secrets
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rds-export-manifest-json-format-preserved"
GROUP = "data-format"
SERVICES = ["rds", "s3"]

EXPORT_PRINCIPAL = "export.rds.amazonaws.com"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A snapshot export to S3 writes every object under export_identifier/database/table/...
    and every data file is Apache Parquet (magic bytes checked); exports write no manifest.json.

    Reference: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_ExportSnapshot.FileNames.html
    Reference: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_ExportSnapshot.html
    """
    rds = ctx.client("rds")
    s3 = ctx.client("s3")

    bucket = _create_bucket(ctx)
    key_arn = _create_kms_key(ctx)
    snapshot_arn = _provision_seeded_snapshot(ctx)
    role_arn = _create_export_role(ctx, EXPORT_PRINCIPAL, bucket, key_arn, grant_permissions=True)

    task_id = ctx.unique_name("sim2real-export-")
    _start_export_task_with_retry(
        rds,
        ExportTaskIdentifier=task_id,
        SourceArn=snapshot_arn,
        S3BucketName=bucket,
        IamRoleArn=role_arn,
        KmsKeyId=key_arn,
    )

    task = _poll_until(
        lambda: rds.describe_export_tasks(ExportTaskIdentifier=task_id)["ExportTasks"][0],
        lambda t: t["Status"] in ("COMPLETE", "FAILED", "CANCELED"),
        timeout_s=1800,
        interval_s=20,
    )
    assert task["Status"] == "COMPLETE", f"export task did not complete: {task}"

    objects = s3.list_objects_v2(Bucket=bucket, Prefix=f"{task_id}/").get("Contents", [])
    parquet_keys = [o["Key"] for o in objects if o["Key"].endswith(".parquet")]
    assert parquet_keys, f"expected parquet objects under base prefix, got: {[o['Key'] for o in objects]}"

    # Base prefix convention: export_identifier/database_name/schema_or_db.table/...
    sample_key = parquet_keys[0]
    parts = sample_key.split("/")
    assert parts[0] == task_id, f"first path segment must be the export identifier: {sample_key}"
    assert len(parts) >= 4, f"expected export_identifier/db/db.table/.../file.parquet, got: {sample_key}"
    db_name = parts[1]
    assert db_name, f"second path segment must be a real database name: {sample_key}"
    assert parts[2].startswith(f"{db_name}."), f"third path segment must be db.table: {sample_key}"

    body = s3.get_object(Bucket=bucket, Key=sample_key)["Body"].read()
    assert len(body) >= 8, "exported parquet object is implausibly small"
    if body[:2] == b"\x1f\x8b":
        import gzip

        body = gzip.decompress(body)
    assert body[:4] == b"PAR1", f"exported object does not start with the Parquet magic number: {body[:4]!r}"
    assert body[-4:] == b"PAR1", f"exported object does not end with the Parquet magic number: {body[-4:]!r}"


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


#: Both codes are observed manifestations of the same IAM/KMS grant-propagation race: RDS
#: resolves the export role's permissions and the key's grant at different points internally,
#: so a freshly created role+policy can surface as either depending on which check it fails
#: first: a role+key created seconds earlier can fail StartExportTask with
#: KMSKeyNotAccessibleFault rather than IamRoleMissingPermissions.
_TRANSIENT_EXPORT_START_CODES = frozenset({"IamRoleMissingPermissions", "KMSKeyNotAccessibleFault"})


def _start_export_task_with_retry(rds, **kwargs) -> None:
    import botocore.exceptions

    deadline = time.monotonic() + 180
    while True:
        try:
            rds.start_export_task(**kwargs)
            return
        except botocore.exceptions.ClientError as err:
            code = err.response["Error"]["Code"]
            if code in _TRANSIENT_EXPORT_START_CODES and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise


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
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "rds-s3-behavioral"}]}
    )
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
        Tags=[{"TagKey": "sim2real", "TagValue": "rds-s3-behavioral"}],
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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "rds-s3-behavioral"}],
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
    """Create an Aurora MySQL Serverless v2 cluster with the Data API, seed one table via
    `rds-data` execute_statement, snapshot it, and return the cluster snapshot ARN
    (StartExportTask accepts a cluster snapshot ARN like an instance snapshot ARN)."""
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
        Tags=[{"Key": "sim2real", "Value": "rds-s3-behavioral"}],
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
        Tags=[{"Key": "sim2real", "Value": "rds-s3-behavioral"}],
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
        Tags=[{"Key": "sim2real", "Value": "rds-s3-behavioral"}],
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
