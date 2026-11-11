"""rds-export-task-s3-bucket-policy-denies-negative."""
from __future__ import annotations

import json
import secrets
import time

from botocore.exceptions import ClientError
from typing import Any

import botocore.exceptions

from behavioral_harness import tags

CHECK = "rds-export-task-s3-bucket-policy-denies-negative"
GROUP = "overly-permissive"
SERVICES = ["rds", "s3"]


@tags("axis:rejection", "cap:c2", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartExportTask with a role the bucket policy denies is rejected with IamRoleMissingPermissions
    and writes nothing, while a role with the same grants that the policy does not name exports to
    COMPLETE with objects."""
    bucket = _create_bucket(ctx)
    denied_role_arn = _create_export_role(ctx, bucket)
    allowed_role_arn = _create_export_role(ctx, bucket)
    key_id = _create_kms_key(ctx, [denied_role_arn, allowed_role_arn])

    denied_prefix = "denied"
    allowed_prefix = "allowed"
    _apply_deny_policy(ctx, bucket, denied_role_arn, denied_prefix)

    instance_id = _create_source_instance(ctx)
    snapshot_arn = _create_snapshot(ctx, instance_id)
    s3 = ctx.client("s3")
    rds = ctx.client("rds")

    # Denied role: the bucket policy blocks s3:PutObject* under this prefix for this role.
    # RDS probes the role's effective S3 write access at StartExportTask call time (before
    # ever creating a pollable task), so the bucket-policy Deny surfaces as a synchronous
    # ClientError rather than an async FAILED task.
    bad_task_id = ctx.unique_name("sim2real-rds-bucketdeny-bad-")
    ctx.on_cleanup(lambda: _best_effort_cancel(rds, bad_task_id))
    error = _client_error(
        lambda: rds.start_export_task(
            ExportTaskIdentifier=bad_task_id,
            SourceArn=snapshot_arn,
            S3BucketName=bucket,
            IamRoleArn=denied_role_arn,
            KmsKeyId=key_id,
            S3Prefix=denied_prefix,
            ExportOnly=["mysql"],
        )
    )
    assert error.get("Code") == "IamRoleMissingPermissions", (
        f"expected StartExportTask to reject a role denied by bucket policy with "
        f"IamRoleMissingPermissions, got {error}"
    )
    expected_message = (
        f"The IAM role {denied_role_arn} isn't authorized to call s3:PutObject on the S3 bucket {bucket}."
    )
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )
    assert _list_all_keys(s3, bucket, prefix=denied_prefix) == [], (
        "no objects should have been written under the bucket-policy-denied prefix"
    )

    # Positive control: a second role, never named in the Deny statement, exports the
    # identical snapshot to the same bucket and completes.
    good_task_id = ctx.unique_name("sim2real-rds-bucketdeny-good-")
    _start_export_with_retry(
        ctx,
        good_task_id,
        snapshot_arn,
        bucket,
        allowed_role_arn,
        key_id,
        s3_prefix=allowed_prefix,
        export_only=["mysql"],
    )
    good_task = _wait_export_terminal(ctx, good_task_id)
    assert good_task["Status"] == "COMPLETE", (
        f"positive-control export did not complete: status={good_task['Status']} "
        f"cause={good_task.get('FailureCause')}"
    )
    assert _list_all_keys(s3, bucket, prefix=allowed_prefix), (
        "expected objects under the allowed export prefix, written by the role the "
        "Deny statement never named"
    )


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
    name = ctx.unique_name("sim2real-rds-bpdeny-").lower().replace("_", "-")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "rds-bucketdeny"}]}
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


def _apply_deny_policy(ctx, bucket, role_arn, denied_prefix):
    s3 = ctx.client("s3")
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyExportRoleUnderDeniedPrefix",
                "Effect": "Deny",
                "Principal": {"AWS": role_arn},
                "Action": "s3:PutObject*",
                "Resource": f"arn:aws:s3:::{bucket}/{denied_prefix}/*",
            }
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))


def _create_export_role(ctx, bucket_name) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-rds-bpdeny-role-")
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
        Tags=[{"Key": "sim2real", "Value": "rds-bucketdeny"}],
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
    return role_arn


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    try:
        for pol in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    iam.delete_role(RoleName=role_name)


def _create_key_with_retry(kms, policy, timeout_s=60):
    # The key policy names a just-created IAM role as a Principal; IAM role creation
    # is eventually consistent, so KMS can reject the ARN as an "invalid principal"
    # for a short window right after create_role returns.
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return kms.create_key(
                Description="sim2real rds->s3 bucket-policy-deny test key",
                Policy=json.dumps(policy),
                Tags=[{"TagKey": "sim2real", "TagValue": "rds-bucketdeny"}],
            )
        except botocore.exceptions.ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "MalformedPolicyDocumentException" and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


def _create_kms_key(ctx, role_arns: list[str]) -> str:
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
                "Principal": {"AWS": role_arns},
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


def _gen_password() -> str:
    return "Aa1!" + secrets.token_urlsafe(12)


def _create_source_instance(ctx) -> str:
    rds = ctx.client("rds")
    identifier = ctx.unique_name("sim2real-rds-bpdeny-src-")
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
        Tags=[{"Key": "sim2real", "Value": "rds-bucketdeny"}],
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
    snap_id = ctx.unique_name("sim2real-rds-bpdeny-snap-")
    rds.create_db_snapshot(
        DBSnapshotIdentifier=snap_id,
        DBInstanceIdentifier=instance_id,
        Tags=[{"Key": "sim2real", "Value": "rds-bucketdeny"}],
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


def _client_error(fn) -> dict:
    try:
        result = fn()
    except botocore.exceptions.ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _best_effort_cancel(rds, task_id):
    try:
        rds.cancel_export_task(ExportTaskIdentifier=task_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExportTaskNotFound":
            raise


def _start_export_with_retry(
    ctx, task_id, source_arn, bucket, role_arn, kms_key_id, s3_prefix=None, export_only=None
):
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
