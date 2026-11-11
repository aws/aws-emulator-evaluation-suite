"""rds-export-snapshot-to-s3-positive."""
from __future__ import annotations

import json
import time
import uuid
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "rds-export-snapshot-to-s3-positive"
GROUP = "event-propagation"
SERVICES = ["rds", "s3"]

FULL_S3_ACTIONS = [
    "s3:PutObject*",
    "s3:GetObject*",
    "s3:ListBucket",
    "s3:DeleteObject*",
    "s3:GetBucketLocation",
]


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A correctly-trusted export role writes real exported snapshot objects into S3."""
    bucket = _create_bucket(ctx)
    kms_key_arn = _create_kms_key(ctx)
    role_arn = _create_export_role(
        ctx, "export.rds.amazonaws.com", bucket, kms_key_arn, FULL_S3_ACTIONS
    )
    snapshot_arn = _create_snapshot_source(ctx)

    rds = ctx.client("rds")
    export_id = ctx.unique_name("sim2real-export-")
    _start_export_task(
        rds,
        retry_missing_permissions=True,
        ExportTaskIdentifier=export_id,
        SourceArn=snapshot_arn,
        S3BucketName=bucket,
        IamRoleArn=role_arn,
        KmsKeyId=kms_key_arn,
    )
    ctx.on_cleanup(lambda: _cancel_export_task_ignore(rds, export_id))

    final = _wait_export_task(rds, export_id, timeout_s=2700, interval_s=20)
    assert final["Status"] == "COMPLETE", (
        f"export task ended in {final['Status']}: {final.get('FailureCause')}"
    )

    s3 = ctx.client("s3")
    keys = [o["Key"] for o in s3.list_objects_v2(Bucket=bucket).get("Contents", [])]
    assert keys, "export task reported COMPLETE but wrote no objects to S3"
    assert all(k.startswith(export_id) for k in keys), keys
    # The source DB has no table data to partition into Parquet files, but RDS always writes an
    # export_info_<id>.json summary object describing the completed task -- its landing in the
    # target bucket IS the cross-service delivery effect under test.
    info_keys = [k for k in keys if k.endswith(f"export_info_{export_id}.json")]
    assert info_keys, f"no export_info summary object found among exported objects: {keys}"
    manifest = json.loads(s3.get_object(Bucket=bucket, Key=info_keys[0])["Body"].read())
    assert isinstance(manifest, dict) and manifest, (
        f"export_info.json parsed to an empty or non-dict value: {manifest!r}"
    )
    assert export_id in json.dumps(manifest), (
        f"export_info.json does not reference its own export task id {export_id!r}: {manifest!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=5.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description}; last observed: {last!r}")


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-rds-export-")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "simparity-check", "Value": CHECK}]}
    )

    def _cleanup() -> None:
        resp = s3.list_objects_v2(Bucket=name)
        objs = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
        if objs:
            failed = s3.delete_objects(Bucket=name, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _create_kms_key(ctx) -> str:
    kms = ctx.client("kms")
    key = kms.create_key(
        Description="sim2real rds export key",
        Tags=[{"TagKey": "simparity-check", "TagValue": CHECK}],
    )["KeyMetadata"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key["KeyId"], PendingWindowInDays=7))
    return key["Arn"]


def _create_export_role(
    ctx, trust_service, bucket_name=None, kms_key_arn=None, s3_actions=None
) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-rds-export-role-")
    trust_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": trust_service},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_doc),
        Tags=[{"Key": "simparity-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    if s3_actions and bucket_name:
        statements = [
            {
                "Effect": "Allow",
                "Action": s3_actions,
                "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
            }
        ]
        if kms_key_arn:
            statements.append(
                {
                    "Effect": "Allow",
                    "Action": ["kms:CreateGrant", "kms:DescribeKey"],
                    "Resource": kms_key_arn,
                }
            )
        policy_name = ctx.unique_name("sim2real-rds-export-policy-")
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_snapshot_source(ctx) -> str:
    rds = ctx.client("rds")
    db_id = ctx.unique_name("sim2real-rds-src-")
    password = f"S2r{uuid.uuid4().hex[:16]}Aa1"
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=db_id,
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        AllocatedStorage=20,
        MasterUsername="s2ruser",
        MasterUserPassword=password,
        PubliclyAccessible=False,
        BackupRetentionPeriod=1,
        StorageType="gp2",
        Tags=[{"Key": "simparity-check", "Value": CHECK}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_instance(DBInstanceIdentifier=db_id, SkipFinalSnapshot=True)
    )
    _poll_until(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0][
            "DBInstanceStatus"
        ],
        lambda status: status == "available",
        timeout_s=1800,
        interval_s=20,
        description=f"db instance {db_id} available",
    )
    snap_id = ctx.unique_name("sim2real-rds-snap-")
    rds.create_db_snapshot(
        DBSnapshotIdentifier=snap_id,
        DBInstanceIdentifier=db_id,
        Tags=[{"Key": "simparity-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_snapshot(DBSnapshotIdentifier=snap_id))
    final = _poll_until(
        lambda: rds.describe_db_snapshots(DBSnapshotIdentifier=snap_id)["DBSnapshots"][0],
        lambda snap: snap["Status"] == "available",
        timeout_s=1200,
        interval_s=15,
        description=f"snapshot {snap_id} available",
    )
    return final["DBSnapshotArn"]


def _start_export_task(rds, retry_missing_permissions=False, timeout_s=90.0, **kwargs):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return rds.start_export_task(**kwargs)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if (
                retry_missing_permissions
                and code in ("IamRoleMissingPermissions", "AccessDenied")
                and time.monotonic() < deadline
            ):
                time.sleep(5)
                continue
            raise


def _wait_export_task(rds, export_task_id, timeout_s, interval_s=20.0):
    return _poll_until(
        lambda: rds.describe_export_tasks(ExportTaskIdentifier=export_task_id)["ExportTasks"][0],
        lambda task: task["Status"] in ("COMPLETE", "FAILED", "CANCELED"),
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"export task {export_task_id} terminal",
    )


def _cancel_export_task_ignore(rds, export_task_id) -> None:
    try:
        rds.cancel_export_task(ExportTaskIdentifier=export_task_id)
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
