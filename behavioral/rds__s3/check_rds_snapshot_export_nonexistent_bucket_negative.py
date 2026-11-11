"""rds-snapshot-export-nonexistent-bucket-negative."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rds-snapshot-export-nonexistent-bucket-negative"
GROUP = "permission-boundary"
SERVICES = ["rds", "s3"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """StartExportTask fails immediately against a target S3 bucket that does not exist."""
    bucket = _create_bucket(ctx)
    role_arn = _create_export_role(ctx, bucket)
    key_id = _create_kms_key(ctx)
    snapshot_arn = _create_snapshot(ctx)

    rds = ctx.client("rds")
    s3 = ctx.client("s3")

    # ONE broken thing: the S3 bucket name simply does not exist (role/KMS/snapshot are all valid).
    fake_bucket = ctx.unique_name("sim2real-rds-exp-nobucket-")
    bad_task_id = ctx.unique_name("sim2real-exp-bad-")
    code, message = _error_code(lambda: _start_export_task_with_retry(
        rds,
        ExportTaskIdentifier=bad_task_id,
        SourceArn=snapshot_arn,
        S3BucketName=fake_bucket,
        IamRoleArn=role_arn,
        KmsKeyId=key_id,
    ))
    assert code == "InvalidS3BucketFault", code
    assert message == (
        f"The S3 bucket {fake_bucket} isn't valid. Either it isn't located in the current "
        f"AWS Region or it doesn't exist."
    ), message

    # Effect absent: no export task was created and nothing was delivered anywhere.
    tasks = rds.describe_export_tasks(SourceArn=snapshot_arn)["ExportTasks"]
    assert not any(t["ExportTaskIdentifier"] == bad_task_id for t in tasks), (
        f"bad_task_id={bad_task_id!r} should never appear in describe_export_tasks, got {tasks!r}"
    )

    # Positive control: the same snapshot/role/key export successfully to the real bucket.
    good_task_id = ctx.unique_name("sim2real-exp-good-")
    _start_export_task_with_retry(
        rds,
        ExportTaskIdentifier=good_task_id,
        SourceArn=snapshot_arn,
        S3BucketName=bucket,
        IamRoleArn=role_arn,
        KmsKeyId=key_id,
    )
    task = _poll_until(
        lambda: rds.describe_export_tasks(ExportTaskIdentifier=good_task_id)["ExportTasks"][0],
        lambda t: t["Status"] in ("COMPLETE", "FAILED", "CANCELED"),
        timeout_s=2400,
        interval_s=30,
    )
    assert task["Status"] == "COMPLETE", (
        f"positive control export ended in {task['Status']}: {task.get('FailureCause')}"
    )
    good_objects = s3.list_objects_v2(Bucket=bucket, Prefix=good_task_id).get("Contents", [])
    assert len(good_objects) > 0, (
        f"positive control export COMPLETEd but wrote no objects under prefix {good_task_id!r} in {bucket!r}"
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


def _error_code(fn):
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _start_export_task_with_retry(rds, **kwargs):
    """StartExportTask assumes the export role immediately; IAM's write path is eventually
    consistent, so a role/policy created moments ago can transiently 404 as IamRoleNotFound.
    Retry only that specific, expected-to-clear error — anything else (including the
    InvalidS3BucketFault this check exists to assert) surfaces on the first attempt."""
    from botocore.exceptions import ClientError
    deadline = time.monotonic() + 90.0
    while True:
        try:
            return rds.start_export_task(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "IamRoleNotFound" or time.monotonic() > deadline:
                raise
            time.sleep(2)


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-rds-exp-")
    # us-east-1 is S3's region-less default: CreateBucket rejects an explicit
    # LocationConstraint there, so the literal pins that one region's API quirk, not this bucket.
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
    key_id = kms.create_key(
        Description="sim2real rds export test key",
        Tags=[{"TagKey": "sim2real", "TagValue": "rds-s3-behavioral"}],
    )["KeyMetadata"]["KeyId"]
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
    # IAM's write path is eventually consistent; callers retry the specific
    # IamRoleNotFound this produces via _start_export_task_with_retry instead of sleeping here.
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
