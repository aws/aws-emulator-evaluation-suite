"""rds-snapshot-export-task-creates-s3-objects."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rds-snapshot-export-task-creates-s3-objects"
GROUP = "event-propagation"
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
    """StartExportTask on an RDS snapshot writes exported data-part objects to the target S3 bucket."""
    bucket = _create_bucket(ctx)
    role_arn = _create_export_role(ctx, bucket)
    key_id = _create_kms_key(ctx)
    snapshot_arn = _create_snapshot(ctx)

    rds = ctx.client("rds")
    s3 = ctx.client("s3")
    task_id = ctx.unique_name("sim2real-exp-task-")
    _start_export_with_retry(
        rds,
        ExportTaskIdentifier=task_id,
        SourceArn=snapshot_arn,
        S3BucketName=bucket,
        IamRoleArn=role_arn,
        KmsKeyId=key_id,
    )

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

    contents = s3.list_objects_v2(Bucket=bucket, Prefix=task_id).get("Contents", [])
    assert len(contents) > 0, (
        "expected the export task to write at least one object to S3"
    )
    assert all(obj["Size"] > 0 for obj in contents), (
        f"exported object(s) with size 0: {[o['Key'] for o in contents if o['Size'] == 0]}"
    )


_MANAGED_TAG = {"Key": "sim2real:managed", "Value": "true"}


def _poll_until(probe, predicate, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _start_export_with_retry(rds, timeout_s=180, interval_s=15, **kwargs):
    # IAM/KMS permissions can lag briefly after role/key creation; retry the call itself.
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return rds.start_export_task(**kwargs)
        except ClientError as e:
            if (
                e.response["Error"]["Code"]
                not in ("InvalidParameterValue", "AccessDenied", "KMSAccessDeniedFault")
                or time.monotonic() >= deadline
            ):
                raise
            time.sleep(interval_s)


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-rds-exp-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [_MANAGED_TAG]})

    def _cleanup():
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=name):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _create_kms_key(ctx) -> str:
    kms = ctx.client("kms")
    key_id = kms.create_key(
        Description="sim2real rds export test key",
        Tags=[{"TagKey": _MANAGED_TAG["Key"], "TagValue": _MANAGED_TAG["Value"]}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(
        lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    )
    return key_id


_ALL_S3_ACTIONS = [
    "s3:PutObject*",
    "s3:GetObject*",
    "s3:ListBucket",
    "s3:DeleteObject*",
    "s3:GetBucketLocation",
]


def _create_export_role(ctx, bucket_name) -> str:
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
        Tags=[_MANAGED_TAG],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": _ALL_S3_ACTIONS,
                "Resource": [
                    f"arn:aws:s3:::{bucket_name}",
                    f"arn:aws:s3:::{bucket_name}/*",
                ],
            },
            {
                # The export process assumes this role to use the KMS key; without this the
                # export task fails with KMSAccessDeniedFault regardless of the key's own policy.
                "Effect": "Allow",
                "Action": ["kms:CreateGrant", "kms:DescribeKey"],
                "Resource": "*",
            },
        ],
    }
    policy_name = ctx.unique_name("sim2real-rds-export-policy-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(policy_doc),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    )
    return role_arn


def _create_snapshot(ctx) -> str:
    rds = ctx.client("rds")
    db_id = ctx.unique_name("sim2real-rds-exp-db-")
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=db_id,
        Engine="mysql",
        DBInstanceClass="db.t3.micro",
        AllocatedStorage=20,
        MasterUsername="s2ruser",
        MasterUserPassword="S2rTestPassw0rd1",
        BackupRetentionPeriod=0,
        PubliclyAccessible=False,
        Tags=[_MANAGED_TAG],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_instance(
            DBInstanceIdentifier=db_id, SkipFinalSnapshot=True
        )
    )
    _poll_until(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0][
            "DBInstanceStatus"
        ],
        lambda s: s == "available",
        timeout_s=1800,
        interval_s=30,
    )

    snap_id = ctx.unique_name("sim2real-rds-exp-snap-")
    rds.create_db_snapshot(
        DBSnapshotIdentifier=snap_id, DBInstanceIdentifier=db_id, Tags=[_MANAGED_TAG]
    )
    ctx.on_cleanup(lambda: rds.delete_db_snapshot(DBSnapshotIdentifier=snap_id))
    snap = _poll_until(
        lambda: rds.describe_db_snapshots(DBSnapshotIdentifier=snap_id)["DBSnapshots"][
            0
        ],
        lambda s: s["Status"] == "available",
        timeout_s=1800,
        interval_s=30,
    )
    return snap["DBSnapshotArn"]


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
