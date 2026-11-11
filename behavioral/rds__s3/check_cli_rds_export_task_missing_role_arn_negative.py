"""cli-rds-export-task-missing-role-arn-negative."""
from __future__ import annotations

import json
import secrets
import time

from botocore.exceptions import ClientError

import botocore

from behavioral_harness import tags

CHECK = "cli-rds-export-task-missing-role-arn-negative"
GROUP = "overly-permissive"
SERVICES = ["rds", "s3"]


@tags(
    "axis:rejection",
    "cap:c1",
    "cap:c4",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """start-export-task with a nonexistent --iam-role-arn fails with KMSKeyNotAccessibleFault (RDS resolves
    the KMS grant through the named role first) and leaves the bucket empty, while the same snapshot,
    bucket and key with a valid role export objects to S3."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    rds = ctx.client("rds")
    kms = ctx.client("kms")

    bucket = ctx.unique_name("sim2real-rds-export-neg-")
    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_bucket(s3, bucket))

    key_id = kms.create_key(Description="sim2real rds export negative key")["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    role_name = ctx.unique_name("sim2real-rds-export-neg-role-")
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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = "s3-export-access"
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
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            },
            {
                "Effect": "Allow",
                "Action": ["kms:CreateGrant", "kms:DescribeKey"],
                "Resource": key_id,
            },
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    db_id = ctx.unique_name("sim2real-rds-export-neg-db-")
    password = "Sim2Real-" + secrets.token_hex(8)
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=db_id,
        Engine="postgres",
        DBInstanceClass="db.t3.micro",
        MasterUsername="dbadmin",
        MasterUserPassword=password,
        AllocatedStorage=20,
        PubliclyAccessible=False,
        BackupRetentionPeriod=0,
        Tags=[{"Key": "sim2real", "Value": "rds-s3-behavioral"}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_instance(DBInstanceIdentifier=db_id, SkipFinalSnapshot=True)
    )
    _wait_db_instance_available(ctx, rds, db_id)

    snapshot_id = ctx.unique_name("sim2real-rds-export-neg-snap-")
    rds.create_db_snapshot(DBSnapshotIdentifier=snapshot_id, DBInstanceIdentifier=db_id)
    ctx.on_cleanup(lambda: rds.delete_db_snapshot(DBSnapshotIdentifier=snapshot_id))
    snapshot = _wait_db_snapshot_available(ctx, rds, snapshot_id)
    snapshot_arn = snapshot["DBSnapshotArn"]

    bogus_role_arn = role_arn[:-4] + "0000"  # syntactically valid ARN, no such role exists
    bad_export_id = ctx.unique_name("sim2real-rds-export-neg-bad-")
    code, message = _client_error(
        lambda: rds.start_export_task(
            ExportTaskIdentifier=bad_export_id,
            SourceArn=snapshot_arn,
            S3BucketName=bucket,
            IamRoleArn=bogus_role_arn,
            KmsKeyId=key_id,
        )
    )
    assert code == "KMSKeyNotAccessibleFault", f"expected KMSKeyNotAccessibleFault, got {code}"
    assert message == (
        f"The specified KMS key [{key_id}] does not exist, is not enabled or you do not have "
        "permissions to access it."
    ), f"unexpected KMSKeyNotAccessibleFault message: {message!r}"

    listing = s3.list_objects_v2(Bucket=bucket)
    assert listing.get("KeyCount", 0) == 0, "no export ran, but S3 bucket is non-empty"

    # Positive control: same snapshot/bucket/KMS key, only the role is valid. IAM's propagation
    # to RDS is eventually consistent, so the identical call is retried on
    # IamRoleNotFound/IamRoleMissingPermissions.
    good_export_id = ctx.unique_name("sim2real-rds-export-neg-good-")
    ctx.on_cleanup(lambda: _cancel_export_task_best_effort(rds, good_export_id))
    _start_export_task_with_role_propagation_retry(
        ctx,
        rds,
        export_task_id=good_export_id,
        source_arn=snapshot_arn,
        bucket=bucket,
        role_arn=role_arn,
        key_id=key_id,
    )
    task = _wait_export_task_terminal(ctx, rds, good_export_id, timeout_s=1800.0)
    assert task["Status"] == "COMPLETE", (
        f"positive-control export with a valid role did not complete: {task}"
    )

    # Terminal read at the consumer: the export must have actually landed objects in S3, not
    # merely reported a non-failed RDS-side status.
    export_listing = s3.list_objects_v2(Bucket=bucket)
    assert export_listing.get("KeyCount", 0) > 0, (
        "export task reported COMPLETE but the destination S3 bucket has no objects"
    )


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises:
    AWS refuses this call."""
    try:
        result = fn()
    except botocore.exceptions.ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _create_bucket(ctx, s3, bucket_name: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket_name))


def _empty_bucket(s3, bucket_name: str) -> None:
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket_name):
        objects = page.get("Contents", [])
        if not objects:
            continue
        failed = s3.delete_objects(
            Bucket=bucket_name,
            Delete={"Objects": [{"Key": obj["Key"]} for obj in objects]},
        ).get("Errors")
        if failed:
            raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")


def _cancel_export_task_best_effort(rds, export_task_id: str) -> None:
    try:
        rds.cancel_export_task(ExportTaskIdentifier=export_task_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExportTaskNotFound":
            raise


def _wait_db_instance_available(ctx, rds, db_instance_id: str, timeout_s=1200.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = rds.describe_db_instances(DBInstanceIdentifier=db_instance_id)
        status = resp["DBInstances"][0]["DBInstanceStatus"]
        if status == "available":
            return resp["DBInstances"][0]
        if status in ("failed", "incompatible-parameters"):
            raise AssertionError(f"DB instance entered unexpected status {status}")
        time.sleep(interval_s)
    raise AssertionError(f"DB instance {db_instance_id} did not become available within {timeout_s}s")


def _wait_db_snapshot_available(ctx, rds, snapshot_id: str, timeout_s=900.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = rds.describe_db_snapshots(DBSnapshotIdentifier=snapshot_id)
        snap = resp["DBSnapshots"][0]
        if snap["Status"] == "available":
            return snap
        if snap["Status"] in ("failed",):
            raise AssertionError(f"DB snapshot entered unexpected status {snap['Status']}")
        time.sleep(interval_s)
    raise AssertionError(f"DB snapshot {snapshot_id} did not become available within {timeout_s}s")


def _start_export_task_with_role_propagation_retry(
    ctx, rds, *, export_task_id, source_arn, bucket, role_arn, key_id, timeout_s=90.0, interval_s=10.0
):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            rds.start_export_task(
                ExportTaskIdentifier=export_task_id,
                SourceArn=source_arn,
                S3BucketName=bucket,
                IamRoleArn=role_arn,
                KmsKeyId=key_id,
            )
            return
        except botocore.exceptions.ClientError as err:
            code = err.response["Error"]["Code"]
            if code not in ("IamRoleNotFound", "IamRoleMissingPermissions"):
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"start-export-task with a valid role kept failing on IAM propagation "
                    f"({code}) after {timeout_s}s"
                ) from err
            time.sleep(interval_s)


def _wait_export_task_terminal(ctx, rds, export_task_id: str, timeout_s=1800.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = rds.describe_export_tasks(ExportTaskIdentifier=export_task_id)
        tasks = resp.get("ExportTasks", [])
        if tasks:
            last = tasks[0]
            if last["Status"] in ("COMPLETE", "FAILED", "CANCELED"):
                return last
        time.sleep(interval_s)
    raise AssertionError(
        f"export task {export_task_id} did not reach a terminal status within {timeout_s}s "
        f"(last={last})"
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
