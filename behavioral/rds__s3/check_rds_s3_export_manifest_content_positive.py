"""rds-s3-export-manifest-content-positive."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError
import uuid

import botocore.exceptions

from behavioral_harness import tags

CHECK = "rds-s3-export-manifest-content-positive"
GROUP = "snapshot-export"
SERVICES = ["rds", "s3"]


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
    """A completed RDS export task writes a JSON metadata/manifest object into
    the S3 export prefix whose content correctly references the source DB
    snapshot ARN used to start the export."""
    rds = ctx.client("rds")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    kms = ctx.client("kms")

    bucket = _create_bucket(ctx, s3)
    key_arn = _create_kms_key(ctx, kms)
    role_arn = _create_export_role(ctx, iam, bucket, key_arn)
    snapshot_arn = _create_snapshot(ctx, rds)

    export_task_id = ctx.unique_name("sim2real-rds-export-")
    _start_export_task_with_retry(
        rds,
        ExportTaskIdentifier=export_task_id,
        SourceArn=snapshot_arn,
        S3BucketName=bucket,
        IamRoleArn=role_arn,
        KmsKeyId=key_arn,
    )
    ctx.on_cleanup(lambda: _cancel_export_task_quietly(rds, export_task_id))

    task = _wait_export_task_terminal(rds, export_task_id)
    assert task["Status"] == "COMPLETE", (
        f"export task ended in {task['Status']!r}: {task.get('FailureCause')}"
    )

    keys = _list_objects(s3, bucket, prefix=f"{export_task_id}/")
    json_keys = [k for k in keys if k.endswith(".json")]
    assert json_keys, (
        f"no JSON metadata object found under {export_task_id}/; objects={keys[:10]}"
    )

    matches = []
    for key in json_keys:
        body = (
            s3.get_object(Bucket=bucket, Key=key)["Body"]
            .read()
            .decode("utf-8", errors="replace")
        )
        if snapshot_arn in body:
            matches.append(key)
    assert matches, (
        f"none of the export's JSON metadata objects {json_keys} reference the source "
        f"snapshot ARN {snapshot_arn}"
    )


def _create_bucket(ctx, s3):
    bucket = ctx.unique_name("sim2real-rds-export-")
    # S3's CreateBucket rejects an explicit LocationConstraint for us-east-1 itself.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": "rds-s3-behavioral"}]},
    )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    return bucket


def _empty_and_delete_bucket(s3, bucket):
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        contents = page.get("Contents", [])
        if contents:
            failed = s3.delete_objects(
                Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in contents]}
            ).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _create_kms_key(ctx, kms):
    key = kms.create_key(
        Description="sim2real RDS snapshot export test key",
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": "rds-s3-behavioral"}],
    )
    key_id = key["KeyMetadata"]["KeyId"]
    key_arn = key["KeyMetadata"]["Arn"]
    ctx.on_cleanup(
        lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    )
    return key_arn


def _create_export_role(ctx, iam, bucket, key_arn, *, s3_actions=None, extra_kms=True):
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
    role_name = ctx.unique_name("sim2real-rds-exp-role-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "rds-s3-behavioral"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    statements = [
        {
            "Sid": "S3Access",
            "Effect": "Allow",
            "Action": s3_actions
            if s3_actions is not None
            else [
                "s3:PutObject*",
                "s3:ListBucket",
                "s3:GetObject*",
                "s3:DeleteObject*",
                "s3:GetBucketLocation",
            ],
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        }
    ]
    if extra_kms:
        statements.append(
            {
                "Sid": "KmsAccess",
                "Effect": "Allow",
                "Action": ["kms:CreateGrant", "kms:DescribeKey"],
                "Resource": key_arn,
            }
        )
    policy_name = f"{role_name}-policy"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    )
    return role_arn


def _create_snapshot(ctx, rds):
    instance_id = ctx.unique_name("sim2real-rds-exp-")
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=instance_id,
        DBInstanceClass="db.t3.micro",
        Engine="mysql",
        MasterUsername="simadmin",
        MasterUserPassword="Sim2Real-" + uuid.uuid4().hex[:12],
        AllocatedStorage=20,
        BackupRetentionPeriod=0,
        StorageType="gp2",
        PubliclyAccessible=False,
        MultiAZ=False,
        Tags=[{"Key": "sim2real", "Value": "rds-s3-behavioral"}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_instance(
            DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True
        )
    )
    _wait_db_instance_available(rds, instance_id)

    snapshot_id = ctx.unique_name("sim2real-rds-exp-snap-")
    rds.create_db_snapshot(
        DBSnapshotIdentifier=snapshot_id,
        DBInstanceIdentifier=instance_id,
        Tags=[{"Key": "sim2real", "Value": "rds-s3-behavioral"}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_snapshot(DBSnapshotIdentifier=snapshot_id))
    snapshot = _wait_snapshot_available(rds, snapshot_id)
    return snapshot["DBSnapshotArn"]


def _wait_db_instance_available(rds, instance_id, timeout_s=2400.0, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        resp = rds.describe_db_instances(DBInstanceIdentifier=instance_id)
        status = resp["DBInstances"][0]["DBInstanceStatus"]
        if status == "available":
            return resp["DBInstances"][0]
        if status in ("failed", "incompatible-parameters", "incompatible-network"):
            raise AssertionError(
                f"DB instance {instance_id} entered terminal status {status}"
            )
        time.sleep(interval_s)
    raise AssertionError(
        f"DB instance {instance_id} did not become available within {timeout_s}s (last={status})"
    )


def _wait_snapshot_available(rds, snapshot_id, timeout_s=1800.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        resp = rds.describe_db_snapshots(DBSnapshotIdentifier=snapshot_id)
        snap = resp["DBSnapshots"][0]
        status = snap["Status"]
        if status == "available":
            return snap
        if status == "failed":
            raise AssertionError(f"snapshot {snapshot_id} failed")
        time.sleep(interval_s)
    raise AssertionError(
        f"snapshot {snapshot_id} did not become available within {timeout_s}s (last={status})"
    )


def _wait_export_task_terminal(rds, export_task_id, timeout_s=3600.0, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    task = None
    while time.monotonic() < deadline:
        resp = rds.describe_export_tasks(ExportTaskIdentifier=export_task_id)
        tasks = resp["ExportTasks"]
        if tasks:
            task = tasks[0]
            if task["Status"] in ("COMPLETE", "FAILED", "CANCELED"):
                return task
        time.sleep(interval_s)
    raise AssertionError(
        f"export task {export_task_id} did not reach a terminal state within {timeout_s}s "
        f"(last={task})"
    )


def _start_export_task_with_retry(rds, *, timeout_s=150.0, interval_s=15.0, **kwargs):
    # A freshly created IAM role/KMS grant can take a short time to propagate; see
    # https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_general.html#troubleshoot_general_eventual-consistency
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


def _cancel_export_task_quietly(rds, export_task_id):
    try:
        rds.cancel_export_task(ExportTaskIdentifier=export_task_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExportTaskNotFound":
            raise


def _list_objects(s3, bucket, prefix):
    keys = []
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        keys.extend(o["Key"] for o in page.get("Contents", []))
    return keys


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
