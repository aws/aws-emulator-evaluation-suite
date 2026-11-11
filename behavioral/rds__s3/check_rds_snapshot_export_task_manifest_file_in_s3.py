"""rds-snapshot-export-task-manifest-file-in-s3."""

from __future__ import annotations

import json
import secrets
import time

from botocore.exceptions import ClientError

import botocore.exceptions

from behavioral_harness import tags

CHECK = "rds-snapshot-export-task-manifest-file-in-s3"
GROUP = "data-format"
SERVICES = ["rds", "s3"]

_TAGS = [{"Key": "sim2real", "Value": "rds-s3-behavioral"}]
_KMS_TAGS = [
    {"TagKey": "sim2real", "TagValue": "rds-s3-behavioral"}
]  # KMS uses TagKey/TagValue, not Key/Value
_ALL_S3_ACTIONS = [
    "s3:PutObject*",
    "s3:GetObject*",
    "s3:ListBucket",
    "s3:DeleteObject*",
    "s3:GetBucketLocation",
]


@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A completed export task writes an export_info_<id>.json manifest that references its own
    task id, alongside real exported Parquet data-part objects, into S3."""
    bucket = _create_bucket(ctx)
    key_arn = _create_kms_key(ctx)
    role_arn = _create_export_role(ctx, bucket, key_arn)
    snapshot_arn = _provision_seeded_snapshot(ctx)

    rds = ctx.client("rds")
    s3 = ctx.client("s3")
    task_id = ctx.unique_name("sim2real-exp-task-")
    _start_export_task_with_retry(
        rds,
        ExportTaskIdentifier=task_id,
        SourceArn=snapshot_arn,
        S3BucketName=bucket,
        IamRoleArn=role_arn,
        KmsKeyId=key_arn,
    )
    ctx.on_cleanup(lambda: _cancel_export_task_quietly(rds, task_id))

    task = _poll_until(
        lambda: rds.describe_export_tasks(ExportTaskIdentifier=task_id)["ExportTasks"][
            0
        ],
        lambda t: t["Status"] in ("COMPLETE", "FAILED", "CANCELED"),
        timeout_s=2400,
        interval_s=30,
    )
    assert task["Status"] == "COMPLETE", (
        f"export task ended in {task['Status']}: {task.get('FailureCause')}"
    )

    objects = s3.list_objects_v2(Bucket=bucket, Prefix=task_id).get("Contents", [])
    keys = [obj["Key"] for obj in objects]
    sizes = {obj["Key"]: obj["Size"] for obj in objects}

    # RDS always writes exactly one `<task_id>/export_info_<task_id>.json` summary object
    # describing the completed task -- that IS the manifest under test.
    manifest_key = f"{task_id}/export_info_{task_id}.json"
    assert manifest_key in keys, (
        f"expected export_info manifest at {manifest_key!r}, found {keys}"
    )

    body = s3.get_object(Bucket=bucket, Key=manifest_key)["Body"].read()
    manifest = json.loads(body)
    assert isinstance(manifest, dict) and manifest, (
        "export_info manifest should be a non-empty JSON object"
    )
    # The manifest describes THIS task -- its own identifier must appear somewhere in it.
    assert task_id in json.dumps(manifest), (
        f"export_info manifest does not reference its own export task id {task_id!r}: {manifest!r}"
    )

    parquet_keys = [k for k in keys if k.endswith(".parquet")]
    assert parquet_keys, (
        f"expected exported .parquet data-part objects alongside the manifest, found {keys}"
    )
    assert all(sizes[k] > 0 for k in parquet_keys), (
        f"exported parquet data-part object(s) are empty: {[k for k in parquet_keys if sizes[k] == 0]}"
    )


def _poll_until(probe, predicate, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _try(fn) -> bool:
    try:
        fn()
        return True
    except Exception:
        return False


def _best_effort(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "DBClusterNotFoundFault",
            "DBClusterSnapshotNotFoundFault",
            "DBInstanceNotFound",
            "NoSuchEntity",
            "NotFoundException",
            "ResourceNotFoundException",
        ):
            raise


def _random_password() -> str:
    return "Aa1" + secrets.token_urlsafe(14)


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-rds-exp-")
    if ctx.region == "us-east-1":
        # us-east-1 is the only region where CreateBucket rejects a LocationConstraint.
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _TAGS})

    def _cleanup():
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=name):
            objs = [{"Key": obj["Key"]} for obj in page.get("Contents", [])]
            if objs:
                failed = s3.delete_objects(Bucket=name, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _create_kms_key(ctx) -> str:
    kms = ctx.client("kms")
    key = kms.create_key(Description="sim2real rds export test key", Tags=_KMS_TAGS)[
        "KeyMetadata"
    ]
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: kms.schedule_key_deletion(KeyId=key["KeyId"], PendingWindowInDays=7)
        )
    )
    return key["Arn"]


def _create_export_role(ctx, bucket_name, key_arn) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-rds-export-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "export.rds.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=_TAGS,
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _best_effort(lambda: iam.delete_role(RoleName=role_name)))

    statements = [
        {
            "Sid": "S3Export",
            "Effect": "Allow",
            "Action": _ALL_S3_ACTIONS,
            "Resource": [
                f"arn:aws:s3:::{bucket_name}",
                f"arn:aws:s3:::{bucket_name}/*",
            ],
        },
        {
            "Sid": "KmsExport",
            "Effect": "Allow",
            "Action": ["kms:CreateGrant", "kms:DescribeKey"],
            "Resource": key_arn,
        },
    ]
    policy_name = ctx.unique_name("sim2real-rds-export-policy-")
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
    return role_arn


def _pick_aurora_mysql_version(ctx) -> str:
    """Pick a recent aurora-mysql 3.x engine version (Data API requires 3.02+)."""
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


def _provision_seeded_snapshot(ctx) -> str:
    """Create an Aurora MySQL Serverless v2 cluster with the RDS Data API enabled, seed one real
    user table via `rds-data` execute_statement -- no native SQL driver or CLI required -- snapshot
    the cluster, and return the cluster snapshot ARN. StartExportTask accepts a DB CLUSTER snapshot
    ARN exactly like a DB instance snapshot ARN."""
    rds = ctx.client("rds")
    rds_data = ctx.client("rds-data")
    secretsmanager = ctx.client("secretsmanager")

    engine_version = _pick_aurora_mysql_version(ctx)
    cluster_id = ctx.unique_name("sim2real-rds-exp-cl-")
    password = _random_password()
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-mysql",
        EngineVersion=engine_version,
        MasterUsername="s2ruser",
        MasterUserPassword=password,
        DatabaseName="sim2real",
        ServerlessV2ScalingConfiguration={"MinCapacity": 0.5, "MaxCapacity": 2.0},
        EnableHttpEndpoint=True,
        BackupRetentionPeriod=1,
        StorageEncrypted=True,
        Tags=_TAGS,
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: rds.delete_db_cluster(
                DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True
            )
        )
    )

    instance_id = ctx.unique_name("sim2real-rds-exp-in-")
    rds.create_db_instance(
        DBInstanceIdentifier=instance_id,
        DBClusterIdentifier=cluster_id,
        Engine="aurora-mysql",
        DBInstanceClass="db.serverless",
        Tags=_TAGS,
    )
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: rds.delete_db_instance(
                DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True
            )
        )
    )

    _poll_until(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=instance_id)[
            "DBInstances"
        ][0]["DBInstanceStatus"],
        lambda status: status == "available",
        timeout_s=1800,
        interval_s=20,
    )
    cluster_arn = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)[
        "DBClusters"
    ][0]["DBClusterArn"]

    secret_name = ctx.unique_name("sim2real-rds-exp-secret-")
    secret_arn = secretsmanager.create_secret(
        Name=secret_name,
        SecretString=json.dumps({"username": "s2ruser", "password": password}),
        Tags=_TAGS,
    )["ARN"]
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: secretsmanager.delete_secret(
                SecretId=secret_arn, ForceDeleteWithoutRecovery=True
            )
        )
    )

    def _seed():
        rds_data.execute_statement(
            resourceArn=cluster_arn,
            secretArn=secret_arn,
            database="sim2real",
            sql="CREATE TABLE IF NOT EXISTS export_rows (id INT PRIMARY KEY, val VARCHAR(50))",
        )
        rds_data.execute_statement(
            resourceArn=cluster_arn,
            secretArn=secret_arn,
            database="sim2real",
            sql=(
                "INSERT INTO export_rows (id, val) VALUES (1,'alpha'),(2,'beta'),(3,'gamma') "
                "ON DUPLICATE KEY UPDATE val = VALUES(val)"
            ),
        )

    _poll_until(
        lambda: _try(_seed), lambda ok: ok is True, timeout_s=180, interval_s=10
    )

    snap_id = ctx.unique_name("sim2real-rds-exp-snap-")
    rds.create_db_cluster_snapshot(
        DBClusterSnapshotIdentifier=snap_id, DBClusterIdentifier=cluster_id
    )
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: rds.delete_db_cluster_snapshot(DBClusterSnapshotIdentifier=snap_id)
        )
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


def _start_export_task_with_retry(rds, *, timeout_s=150.0, interval_s=15.0, **kwargs):
    # A freshly created IAM role/KMS grant is eventually consistent; retry the specific
    # permission-propagation faults instead of sleeping blind before the call.
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return rds.start_export_task(**kwargs)
        except botocore.exceptions.ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in (
                "IamRoleMissingPermissions",
                "InvalidS3BucketFault",
                "KMSKeyNotAccessibleFault",
            ):
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _cancel_export_task_quietly(rds, task_id) -> None:
    try:
        rds.cancel_export_task(ExportTaskIdentifier=task_id)
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
