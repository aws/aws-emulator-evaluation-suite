"""rds-snapshot-export-to-s3-positive."""
from __future__ import annotations

import json
import secrets
import time

from botocore.exceptions import ClientError
from typing import Any

import botocore.exceptions

from behavioral_harness import tags

CHECK = "rds-snapshot-export-to-s3-positive"
GROUP = "export-delivery"
SERVICES = ["rds", "s3"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartExportTask on a real RDS snapshot writes exported Parquet objects into S3."""
    bucket = _create_bucket(ctx)
    role_name, role_arn = _create_export_role(ctx, bucket)
    key_id = _create_kms_key(ctx, role_arn)
    instance_id = _create_source_instance(ctx)
    snapshot_arn = _create_snapshot(ctx, instance_id)

    task_id = ctx.unique_name("sim2real-rds-exp-task-")
    _start_export_with_retry(
        ctx, task_id, snapshot_arn, bucket, role_arn, key_id, export_only=["mysql"]
    )
    task = _wait_export_terminal(ctx, task_id)
    assert task["Status"] == "COMPLETE", (
        f"export task did not complete: status={task['Status']} "
        f"cause={task.get('FailureCause')}"
    )

    s3 = ctx.client("s3")
    keys = _list_all_keys(s3, bucket)
    assert keys, "export task reported COMPLETE but no objects were written to S3"
    parquet_keys = [k for k in keys if k.endswith(".parquet")]
    assert parquet_keys, f"no .parquet objects found among exported keys: {keys[:10]}"
    mysql_keys = [k for k in parquet_keys if "mysql" in k]
    assert mysql_keys, f"expected exported keys to reference the 'mysql' database, got: {keys[:10]}"

    head = s3.head_object(Bucket=bucket, Key=mysql_keys[0])
    assert head["ContentLength"] > 0, "exported Parquet object is empty"


def _wait_for(probe, predicate, timeout_s, interval_s, desc):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {desc}; last-seen={last!r}")


def _list_all_keys(s3, bucket, prefix=""):
    keys: list[str] = []
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        keys.extend(o["Key"] for o in page.get("Contents", []))
    return keys


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-rds-exp-").lower().replace("_", "-")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        # us-east-1 is the one region that rejects an explicit LocationConstraint.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "rds-s3-behavioral"}]}
    )
    return name


def _empty_and_delete_bucket(ctx, bucket):
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _create_export_role(ctx, bucket_name) -> tuple[str, str]:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-rds-exp-role-")
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
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
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
                "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="s3-export-access", PolicyDocument=json.dumps(policy_doc)
    )
    return role_name, role_arn


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    try:
        for pol in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    iam.delete_role(RoleName=role_name)


def _create_kms_key(ctx, role_arn) -> str:
    kms = ctx.client("kms")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "EnableRootAccess",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "kms:*",
                "Resource": "*",
            },
            {
                "Sid": "AllowExportRoleUse",
                "Effect": "Allow",
                "Principal": {"AWS": role_arn},
                "Action": [
                    "kms:CreateGrant",
                    "kms:DescribeKey",
                    "kms:GenerateDataKey*",
                    "kms:Decrypt",
                    "kms:Encrypt",
                ],
                "Resource": "*",
            },
        ],
    }
    resp = _create_key_with_retry(kms, policy)
    key_id = resp["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    return key_id


def _create_key_with_retry(kms, policy):
    """CreateKey can transiently fail with MalformedPolicyDocumentException ("invalid
    principals") right after the role in the policy was created, due to IAM eventual
    consistency. Retry that specific condition; any other error propagates immediately."""
    deadline = time.monotonic() + 90
    while True:
        try:
            return kms.create_key(
                Description="sim2real rds->s3 export test key",
                Policy=json.dumps(policy),
                Tags=[{"TagKey": "sim2real", "TagValue": "rds-s3-behavioral"}],
            )
        except botocore.exceptions.ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "MalformedPolicyDocumentException" and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise


def _gen_password() -> str:
    return "Aa1!" + secrets.token_urlsafe(12)


def _create_source_instance(ctx) -> str:
    rds = ctx.client("rds")
    identifier = ctx.unique_name("sim2real-rds-exp-src-")
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=identifier,
        Engine="mysql",
        DBInstanceClass="db.t3.micro",
        MasterUsername="admin",
        MasterUserPassword=_gen_password(),
        AllocatedStorage=20,
        PubliclyAccessible=False,
        BackupRetentionPeriod=0,
        Tags=[{"Key": "sim2real", "Value": "rds-s3-behavioral"}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_instance(DBInstanceIdentifier=identifier, SkipFinalSnapshot=True)
    )
    _wait_for(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=identifier)["DBInstances"][0],
        lambda inst: inst["DBInstanceStatus"] == "available",
        timeout_s=1200,
        interval_s=30,
        desc=f"instance {identifier} available",
    )
    return identifier


def _create_snapshot(ctx, instance_id) -> str:
    rds = ctx.client("rds")
    snap_id = ctx.unique_name("sim2real-rds-exp-snap-")
    rds.create_db_snapshot(
        DBSnapshotIdentifier=snap_id,
        DBInstanceIdentifier=instance_id,
        Tags=[{"Key": "sim2real", "Value": "rds-s3-behavioral"}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_snapshot(DBSnapshotIdentifier=snap_id))
    snap = _wait_for(
        lambda: rds.describe_db_snapshots(DBSnapshotIdentifier=snap_id)["DBSnapshots"][0],
        lambda s: s["Status"] == "available",
        timeout_s=900,
        interval_s=20,
        desc=f"snapshot {snap_id} available",
    )
    return snap["DBSnapshotArn"]


def _start_export_with_retry(
    ctx, task_id, source_arn, bucket, role_arn, kms_key_id, s3_prefix=None, export_only=None
):
    """StartExportTask can transiently fail with IamRoleMissingPermissions right after
    the role/policy was created, due to IAM eventual consistency. Retry that specific
    condition; any other error propagates immediately."""
    rds = ctx.client("rds")
    kwargs: dict[str, Any] = dict(
        ExportTaskIdentifier=task_id,
        SourceArn=source_arn,
        S3BucketName=bucket,
        IamRoleArn=role_arn,
        KmsKeyId=kms_key_id,
    )
    if s3_prefix is not None:
        kwargs["S3Prefix"] = s3_prefix
    if export_only is not None:
        kwargs["ExportOnly"] = export_only

    deadline = time.monotonic() + 120
    while True:
        try:
            return rds.start_export_task(**kwargs)
        except botocore.exceptions.ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "IamRoleMissingPermissions" and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise


def _wait_export_terminal(ctx, task_id, timeout_s=1800, interval_s=20):
    rds = ctx.client("rds")
    return _wait_for(
        lambda: rds.describe_export_tasks(ExportTaskIdentifier=task_id)["ExportTasks"][0],
        lambda t: t["Status"] in ("COMPLETE", "FAILED", "CANCELED"),
        timeout_s=timeout_s,
        interval_s=interval_s,
        desc=f"export task {task_id} terminal",
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
