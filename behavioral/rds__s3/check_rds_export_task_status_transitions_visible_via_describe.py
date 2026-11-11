"""rds-export-task-status-transitions-visible-via-describe."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

import botocore.exceptions

from behavioral_harness import tags

CHECK = "rds-export-task-status-transitions-visible-via-describe"
GROUP = "state-propagation"
SERVICES = ["rds", "s3"]

# Coarse ordering of ExportTask.Status values: DescribeExportTasks must never regress
# to an earlier stage once it has advanced (e.g. never go from IN_PROGRESS back to STARTING).
_STAGE = {
    "STARTING": 0,
    "IN_PROGRESS": 1,
    "CANCELING": 1,
    "COMPLETE": 2,
    "FAILED": 2,
    "CANCELED": 2,
}


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """DescribeExportTasks reflects task progress (STARTING/IN_PROGRESS -> COMPLETE) as S3 fills in."""
    bucket = _create_bucket(ctx)
    role_arn = _create_export_role(ctx, bucket)
    key_id = _create_kms_key(ctx)
    snapshot_arn = _create_snapshot(ctx)

    rds = ctx.client("rds")
    s3 = ctx.client("s3")
    task_id = ctx.unique_name("sim2real-exp-task-")
    _start_export_task_with_retry(
        rds,
        ExportTaskIdentifier=task_id,
        SourceArn=snapshot_arn,
        S3BucketName=bucket,
        IamRoleArn=role_arn,
        KmsKeyId=key_id,
    )

    observed_statuses: list[str] = []
    last_stage = -1
    task = None
    deadline = time.monotonic() + 2400
    while time.monotonic() < deadline:
        task = rds.describe_export_tasks(ExportTaskIdentifier=task_id)["ExportTasks"][0]
        status = task["Status"]
        if not observed_statuses or observed_statuses[-1] != status:
            observed_statuses.append(status)
        stage = _STAGE.get(status, last_stage)
        assert stage >= last_stage, f"export task status regressed: observed {observed_statuses}"
        last_stage = stage
        if status in ("COMPLETE", "FAILED", "CANCELED"):
            break
        time.sleep(2)
    else:
        raise AssertionError(f"export task never reached a terminal state, observed {observed_statuses}")

    assert task["Status"] == "COMPLETE", (
        f"export task ended in {task['Status']}: {task.get('FailureCause')}"
    )
    assert task["PercentProgress"] == 100, f"expected PercentProgress 100 at COMPLETE, got {task['PercentProgress']!r}"
    assert len(observed_statuses) >= 2, (
        f"expected DescribeExportTasks to surface at least one intermediate status before "
        f"COMPLETE, only observed {observed_statuses}"
    )
    assert observed_statuses[0] in ("STARTING", "IN_PROGRESS"), (
        f"expected the first observed status to be STARTING or IN_PROGRESS, got {observed_statuses[0]!r} "
        f"(full sequence {observed_statuses})"
    )

    objects = s3.list_objects_v2(Bucket=bucket, Prefix=task_id).get("Contents", [])
    assert len(objects) > 0, "COMPLETE status should correspond to populated S3 objects"


def _poll_until(probe, predicate, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-rds-exp-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})

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
    key_id = kms.create_key(Description="sim2real rds export test key")["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    return key_id


_ALL_S3_ACTIONS = ["s3:PutObject*", "s3:GetObject*", "s3:ListBucket", "s3:DeleteObject*", "s3:GetBucketLocation"]


def _create_export_role(ctx, bucket_name, *, trust_export=True, missing_actions=None) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-rds-export-role-")
    principal = "export.rds.amazonaws.com" if trust_export else "ec2.amazonaws.com"
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": principal}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    missing = set(missing_actions or [])
    actions = [a for a in _ALL_S3_ACTIONS if a not in missing]
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": actions,
            "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
        }],
    }
    policy_name = ctx.unique_name("sim2real-rds-export-policy-")
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _start_export_task_with_retry(rds, *, timeout_s=150.0, interval_s=15.0, **kwargs):
    # IAM is eventually consistent, so a freshly created role/policy may not yet be usable by RDS;
    # retry on the specific propagation errors rather than sleeping a fixed guess up front.
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return rds.start_export_task(**kwargs)
        except botocore.exceptions.ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("IamRoleMissingPermissions", "InvalidS3BucketFault", "KMSKeyNotAccessibleFault"):
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


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
        Tags=[{"Key": "sim2real", "Value": "rds-s3-behavioral"}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: rds.delete_db_instance(DBInstanceIdentifier=db_id, SkipFinalSnapshot=True))
    _poll_until(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0]["DBInstanceStatus"],
        lambda s: s == "available",
        timeout_s=1800,
        interval_s=30,
    )

    snap_id = ctx.unique_name("sim2real-rds-exp-snap-")
    rds.create_db_snapshot(DBSnapshotIdentifier=snap_id, DBInstanceIdentifier=db_id)
    ctx.on_cleanup(lambda: rds.delete_db_snapshot(DBSnapshotIdentifier=snap_id))
    snap = _poll_until(
        lambda: rds.describe_db_snapshots(DBSnapshotIdentifier=snap_id)["DBSnapshots"][0],
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
