"""rds-export-manifest-format-preserved."""
from __future__ import annotations

import json
import re
import secrets
import time

from botocore.exceptions import ClientError
from typing import Any

import botocore.exceptions

from behavioral_harness import tags

CHECK = "rds-export-manifest-format-preserved"
GROUP = "data-format"
SERVICES = ["rds", "s3"]

# Matches both the current convention (with a numeric batch_index folder) and the
# older convention (no batch_index folder), per AWS's documented file naming rules.
_PART_FILE_RE = re.compile(r"(?:\d+/)?part-\d+-[0-9a-fA-F-]+(?:\.gz)?\.parquet$")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """The exported object keys follow AWS's documented
    `export_id/database/database.table/[batch/]part-*.parquet` layout exactly."""
    bucket = _create_bucket(ctx)
    role_name, role_arn = _create_export_role(ctx, bucket)
    key_id = _create_kms_key(ctx, role_arn)
    instance_id = _create_source_instance(ctx)
    snapshot_arn = _create_snapshot(ctx, instance_id)

    task_id = ctx.unique_name("sim2real-rds-fmt-task-")
    _start_export_with_retry(
        ctx,
        task_id,
        snapshot_arn,
        bucket,
        role_arn,
        key_id,
        export_only=["mysql.help_topic"],
    )
    task = _wait_export_terminal(ctx, task_id)
    assert task["Status"] == "COMPLETE", (
        f"export task did not complete: status={task['Status']} cause={task.get('FailureCause')}"
    )

    s3 = ctx.client("s3")
    keys = _list_all_keys(s3, bucket)
    assert keys, "export completed but produced no S3 objects"

    expected_base = f"{task_id}/mysql/mysql.help_topic/"
    matching_base = [k for k in keys if k.startswith(expected_base)]
    assert matching_base, (
        f"expected object keys under documented base prefix {expected_base!r}, got: {keys[:10]}"
    )
    part_files = [k for k in matching_base if _PART_FILE_RE.search(k)]
    assert part_files, (
        f"no object under {expected_base!r} matched the documented "
        f"'part-<idx>-<uuid>.parquet' naming convention; got: {matching_base[:10]}"
    )


_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:check": CHECK}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xsvc_tags_kms() -> list[dict[str, str]]:
    return [{"TagKey": k, "TagValue": v} for k, v in _xsvc_resource_tags().items()]


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
    name = ctx.unique_name("sim2real-rds-fmt-").lower().replace("_", "-")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _xsvc_tags_kv()})
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
    role_name = ctx.unique_name("sim2real-rds-fmt-role-")
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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_xsvc_tags_kv()
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
    root_only_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "EnableRootAccess",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "kms:*",
                "Resource": "*",
            },
        ],
    }
    full_policy = {
        "Version": "2012-10-17",
        "Statement": [
            *root_only_policy["Statement"],
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
    # The key is created with a root-only policy (always a valid principal) so exactly one key
    # is ever created and its cleanup is registered before any policy referencing role_arn is
    # attempted. IAM roles are eventually consistent: KMS may not yet be able to resolve
    # role_arn as a valid principal for a few seconds after CreateRole returns, so retrying the
    # *update* (not the create) cannot orphan a second, unmanaged key.
    resp = kms.create_key(
        Description="sim2real rds->s3 data-format test key",
        Policy=json.dumps(root_only_policy),
        Tags=_xsvc_tags_kms(),
    )
    key_id = resp["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    deadline = time.monotonic() + 60
    while True:
        try:
            kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=json.dumps(full_policy))
            break
        except botocore.exceptions.ClientError as err:
            code = err.response["Error"]["Code"]
            msg = err.response["Error"].get("Message", "")
            if (
                code == "MalformedPolicyDocumentException"
                and "invalid principal" in msg.lower()
                and time.monotonic() < deadline
            ):
                time.sleep(5)
                continue
            raise
    return key_id


def _gen_password() -> str:
    return "Aa1!" + secrets.token_urlsafe(12)


def _create_source_instance(ctx) -> str:
    rds = ctx.client("rds")
    identifier = ctx.unique_name("sim2real-rds-fmt-src-")
    rds.create_db_instance(
        DBInstanceIdentifier=identifier,
        Engine="mysql",
        DBInstanceClass="db.t3.micro",
        MasterUsername="admin",
        MasterUserPassword=_gen_password(),
        AllocatedStorage=20,
        PubliclyAccessible=False,
        BackupRetentionPeriod=0,
        Tags=_xsvc_tags_kv(),
        DBSubnetGroupName=_network_db_subnet_group(ctx, rds),
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
    snap_id = ctx.unique_name("sim2real-rds-fmt-snap-")
    rds.create_db_snapshot(
        DBSnapshotIdentifier=snap_id, DBInstanceIdentifier=instance_id, Tags=_xsvc_tags_kv()
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
