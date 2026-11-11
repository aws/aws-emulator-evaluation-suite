"""iam-role-trust-policy-rds-s3-positive."""
from __future__ import annotations

import json
import secrets
import time

from botocore.exceptions import ClientError
from typing import Any

import botocore.exceptions

from behavioral_harness import tags

CHECK = "iam-role-trust-policy-rds-s3-positive"
GROUP = "iam-trust"
SERVICES = ["rds", "s3"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartExportTask with a role trusted by ec2.amazonaws.com is rejected with IamRoleNotFound and
    its exact message and writes nothing, while the identical role trusted by export.rds.amazonaws.com
    exports the same snapshot to COMPLETE with objects."""
    bucket = _create_bucket(ctx)
    good_role_arn = _create_role(ctx, bucket, trusted_principal="export.rds.amazonaws.com")
    bad_role_arn = _create_role(ctx, bucket, trusted_principal="ec2.amazonaws.com")
    key_id = _create_kms_key(ctx, [good_role_arn, bad_role_arn])
    instance_id = _create_source_instance(ctx)
    snapshot_arn = _create_snapshot(ctx, instance_id)

    # Wrong trust principal: RDS cannot assume this role, so the export must be rejected.
    bad_task_id = ctx.unique_name("sim2real-iamtrust-bad-")
    bad_prefix = "bad-trust-attempt"
    code, message = _error_code(
        lambda: _start_export(
            ctx,
            bad_task_id,
            snapshot_arn,
            bucket,
            bad_role_arn,
            key_id,
            s3_prefix=bad_prefix,
            export_only=["mysql"],
        )
    )
    assert code == "IamRoleNotFound", f"expected IamRoleNotFound, got {code}"
    expected = (
        f"The principal export.rds.amazonaws.com isn't allowed to assume the IAM role {bad_role_arn} "
        f"or the IAM role {bad_role_arn} doesn't exist."
    )
    assert message == expected, message

    s3 = ctx.client("s3")
    assert _list_all_keys(s3, bucket, prefix=bad_prefix) == [], (
        "no objects should have been written when RDS cannot assume the export role"
    )

    # Correct trust principal (export.rds.amazonaws.com): the export must succeed.
    good_task_id = ctx.unique_name("sim2real-iamtrust-good-")
    good_prefix = "good-trust-attempt"
    _start_export_with_retry(
        ctx,
        good_task_id,
        snapshot_arn,
        bucket,
        good_role_arn,
        key_id,
        s3_prefix=good_prefix,
        export_only=["mysql"],
    )
    ctx.on_cleanup(lambda: _cancel_export_task(ctx, good_task_id))
    task = _wait_export_terminal(ctx, good_task_id)
    assert task["Status"] == "COMPLETE", (
        f"export with correctly-trusted role did not complete: status={task['Status']} "
        f"cause={task.get('FailureCause')}"
    )
    assert _list_all_keys(s3, bucket, prefix=good_prefix), (
        "expected objects under the correctly-trusted role's export prefix"
    )


# ===== helpers =====


def _error_code(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, so a target
    accepting a call AWS refuses is reported as such rather than as a code mismatch."""
    try:
        result = fn()
    except botocore.exceptions.ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"expected StartExportTask to reject the wrongly-trusted role, but it SUCCEEDED: {result!r}"
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
    name = ctx.unique_name("sim2real-rds-trust-").lower().replace("_", "-")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "rds-s3-iamtrust"}]}
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


def _create_role(ctx, bucket_name, trusted_principal) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-rds-trust-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": trusted_principal},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "rds-s3-iamtrust"}],
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


def _create_kms_key(ctx, role_arns) -> str:
    kms = ctx.client("kms")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    statements = [
        {
            "Sid": "EnableRootAccess",
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "kms:*",
            "Resource": "*",
        }
    ]
    for i, role_arn in enumerate(role_arns):
        statements.append(
            {
                "Sid": f"AllowExportRoleUse{i}",
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
            }
        )
    policy = {"Version": "2012-10-17", "Statement": statements}
    # KMS validates that every Principal ARN in the key policy resolves to a real IAM entity at
    # CreateKey time, and a role created moments ago may not have propagated yet -- AWS returns
    # MalformedPolicyDocumentException ("invalid principals") for a role that unambiguously
    # exists. Retry through that window instead of guessing how long it needs.
    deadline = time.monotonic() + 90
    while True:
        try:
            resp = kms.create_key(
                Description="sim2real rds->s3 iam-trust test key",
                Policy=json.dumps(policy),
                Tags=[{"TagKey": "sim2real", "TagValue": "rds-s3-iamtrust"}],
            )
            break
        except botocore.exceptions.ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "MalformedPolicyDocumentException" and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise
    key_id = resp["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    return key_id


def _gen_password() -> str:
    return "Aa1!" + secrets.token_urlsafe(12)


def _create_source_instance(ctx) -> str:
    rds = ctx.client("rds")
    identifier = ctx.unique_name("sim2real-rds-trust-src-")
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
        Tags=[{"Key": "sim2real", "Value": "rds-s3-iamtrust"}],
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
    snap_id = ctx.unique_name("sim2real-rds-trust-snap-")
    rds.create_db_snapshot(
        DBSnapshotIdentifier=snap_id,
        DBInstanceIdentifier=instance_id,
        Tags=[{"Key": "sim2real", "Value": "rds-s3-iamtrust"}],
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


def _start_export(
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
    return rds.start_export_task(**kwargs)


def _start_export_with_retry(
    ctx, task_id, source_arn, bucket, role_arn, kms_key_id, s3_prefix=None, export_only=None
):
    deadline = time.monotonic() + 120
    while True:
        try:
            return _start_export(
                ctx,
                task_id,
                source_arn,
                bucket,
                role_arn,
                kms_key_id,
                s3_prefix=s3_prefix,
                export_only=export_only,
            )
        except botocore.exceptions.ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("IamRoleMissingPermissions", "IamRoleNotFound") and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise


def _cancel_export_task(ctx, task_id):
    rds = ctx.client("rds")
    try:
        rds.cancel_export_task(ExportTaskIdentifier=task_id)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "ExportTaskNotFound":
            return
        if code != "InvalidExportTaskStateFault":
            raise
        # A finished export refuses cancellation; only a task still running is a teardown failure.
        status = rds.describe_export_tasks(ExportTaskIdentifier=task_id)["ExportTasks"][0]["Status"]
        if status not in ("COMPLETE", "FAILED", "CANCELED", "CANCELING"):
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
