"""rds-snapshot-export-role-missing-export-trust-negative."""
from __future__ import annotations

import json
import secrets
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rds-snapshot-export-role-missing-export-trust-negative"
GROUP = "permission-boundary"
SERVICES = ["rds", "s3"]

# RDS may reject an unassumable export role either synchronously (StartExportTask itself
# raises) or asynchronously (the task is accepted and settles into FAILED); both are a valid
# rejection signal for this trust boundary.
SYNC_REJECT_CODES = (
    "IamRoleNotFound",
    "InvalidParameterValue",
    "IamRoleMissingPermissions",
    "KMSKeyNotAccessibleFault",
)


@tags("axis:negative-delivery", "cap:c4", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """A role whose trust policy does not allow export.rds.amazonaws.com is rejected for the
    export, synchronously or as a task settling FAILED, and nothing is written to S3, while the
    same role/bucket setup with a correct trust policy proceeds past that stage."""
    rds = ctx.client("rds")
    s3 = ctx.client("s3")

    bucket = _create_export_bucket(ctx)
    kms_key_id, _ = _create_kms_key(ctx)
    snapshot_arn = _create_snapshot_source(ctx)

    # Trust policy allows ec2.amazonaws.com, not export.rds.amazonaws.com,
    # but the attached permissions policy is otherwise fully correct.
    untrusted_role_arn = _create_export_role(
        ctx, allow_s3_put=True, trust_export_service=False, bucket_name=bucket
    )
    fail_export_id = ctx.unique_name("sim2real-export-notrust-").lower()
    fail_prefix = "rds-export-notrust"

    sync_code = _start_export_task(
        rds,
        retry_iam_propagation=False,
        ExportTaskIdentifier=fail_export_id,
        SourceArn=snapshot_arn,
        S3BucketName=bucket,
        IamRoleArn=untrusted_role_arn,
        KmsKeyId=kms_key_id,
        S3Prefix=fail_prefix,
    )
    ctx.on_cleanup(lambda: _cancel_export_quietly(ctx, fail_export_id))

    if sync_code is None:
        status, cause = _poll_until_terminal(ctx, fail_export_id, timeout_s=900, interval_s=15)
        assert status == "FAILED", (
            f"export task {fail_export_id} with an untrusted role ended in {status!r} "
            f"instead of FAILED (cause={cause!r})"
        )
        assert cause, "a FAILED export task should carry a FailureCause"
    else:
        assert sync_code in SYNC_REJECT_CODES, (
            f"unexpected error code rejecting an untrusted role's export task: {sync_code!r}"
        )

    listing = s3.list_objects_v2(Bucket=bucket, Prefix=fail_prefix)
    keys = [o["Key"] for o in listing.get("Contents", []) if fail_export_id in o["Key"]]
    assert keys == [], f"S3 objects were written despite the role never being assumable: {keys!r}"

    # Positive control: same bucket/snapshot/kms key, but the role trusts export.rds.amazonaws.com
    # -- the task must get past the assume-role stage (i.e. not fail). A healthy export can sit in
    # STARTING for several minutes.
    trusted_role_arn = _create_export_role(
        ctx, allow_s3_put=True, trust_export_service=True, bucket_name=bucket
    )
    ok_export_id = ctx.unique_name("sim2real-export-trusted-").lower()
    ok_code = _start_export_task(
        rds,
        retry_iam_propagation=True,
        ExportTaskIdentifier=ok_export_id,
        SourceArn=snapshot_arn,
        S3BucketName=bucket,
        IamRoleArn=trusted_role_arn,
        KmsKeyId=kms_key_id,
        S3Prefix="rds-export-trusted-control",
    )
    assert ok_code is None, f"control export task with a trusted role was rejected: {ok_code!r}"
    ctx.on_cleanup(lambda: _cancel_export_quietly(ctx, ok_export_id))
    ok_status, ok_cause = _poll_until_not_starting(ctx, ok_export_id, timeout_s=900, interval_s=20)
    assert ok_status != "FAILED", f"control export task with a trusted role failed: {ok_cause!r}"


# ===== helpers =====


def _password() -> str:
    raw = secrets.token_urlsafe(24).replace("-", "x").replace("_", "y")
    return (raw + "Aa1bB2")[:32]


def _create_export_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-rds-export-")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "rds-s3-behavioral"}]}
    )
    return name


def _empty_and_delete_bucket(ctx: Any, name: str) -> None:
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=name):
            objs = page.get("Contents", [])
            if objs:
                failed = s3.delete_objects(
                    Bucket=name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
                ).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_kms_key(ctx: Any) -> tuple[str, str]:
    kms = ctx.client("kms")
    key = kms.create_key(
        Description="sim2real rds export test key",
        Tags=[{"TagKey": "sim2real", "TagValue": "rds-s3-behavioral"}],
    )["KeyMetadata"]
    ctx.on_cleanup(
        lambda: kms.schedule_key_deletion(KeyId=key["KeyId"], PendingWindowInDays=7)
    )
    return key["KeyId"], key["Arn"]


def _create_export_role(
    ctx: Any,
    *,
    allow_s3_put: bool,
    trust_export_service: bool,
    bucket_name: str | None,
) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-rds-export-role-")
    principal = "export.rds.amazonaws.com" if trust_export_service else "ec2.amazonaws.com"
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": principal}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "rds-s3-behavioral"}],
    )["Role"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))

    s3_actions = ["s3:ListBucket", "s3:GetObject*", "s3:GetBucketLocation"]
    if allow_s3_put:
        s3_actions += ["s3:PutObject*", "s3:DeleteObject*"]
    resources: Any = "*"
    if bucket_name:
        resources = [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"]
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "S3Export", "Effect": "Allow", "Action": s3_actions, "Resource": resources},
            {
                "Sid": "KmsExport",
                "Effect": "Allow",
                "Action": ["kms:CreateGrant", "kms:DescribeKey"],
                "Resource": "*",
            },
        ],
    }
    policy_name = f"{role_name}-policy"
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role["Arn"]


#: A freshly created, correctly trusted role can be rejected with either code below until
#: IAM/KMS propagate (RDS cannot yet assume the role or use its kms:CreateGrant permission);
#: it is not a trust-boundary rejection and resolves on retry.
_PROPAGATION_CODES = ("IamRoleNotFound", "KMSKeyNotAccessibleFault")


def _start_export_task(
    rds: Any, *, retry_iam_propagation: bool, **kwargs: Any
) -> str | None:
    """Call StartExportTask once (untrusted-role path) or retry _PROPAGATION_CODES for a
    bounded window (trusted-role path, to absorb IAM/KMS's post-creation propagation delay).
    Returns the ClientError code if the call is rejected synchronously, else None."""
    deadline = time.monotonic() + (180.0 if retry_iam_propagation else 0.0)
    while True:
        try:
            rds.start_export_task(**kwargs)
            return None
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if (
                not retry_iam_propagation
                or code not in _PROPAGATION_CODES
                or time.monotonic() > deadline
            ):
                return code
            time.sleep(2)


def _delete_role(ctx: Any, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        for p in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=p)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_snapshot_source(ctx: Any) -> str:
    rds = ctx.client("rds")
    instance_id = ctx.unique_name("sim2real-rds-export-src-").lower()
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=instance_id,
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername="sim2realadmin",
        MasterUserPassword=_password(),
        AllocatedStorage=20,
        BackupRetentionPeriod=0,
        PubliclyAccessible=False,
        Tags=[{"Key": "sim2real", "Value": "rds-s3-behavioral"}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_instance(ctx, instance_id))
    rds.get_waiter("db_instance_available").wait(
        DBInstanceIdentifier=instance_id, WaiterConfig={"Delay": 2, "MaxAttempts": 1200}
    )

    snapshot_id = ctx.unique_name("sim2real-rds-export-snap-").lower()
    rds.create_db_snapshot(
        DBInstanceIdentifier=instance_id,
        DBSnapshotIdentifier=snapshot_id,
        Tags=[{"Key": "sim2real", "Value": "rds-s3-behavioral"}],
    )
    ctx.on_cleanup(lambda: _delete_snapshot(ctx, snapshot_id))
    rds.get_waiter("db_snapshot_available").wait(
        DBSnapshotIdentifier=snapshot_id, WaiterConfig={"Delay": 2, "MaxAttempts": 900}
    )
    desc = rds.describe_db_snapshots(DBSnapshotIdentifier=snapshot_id)["DBSnapshots"][0]
    return desc["DBSnapshotArn"]


def _delete_instance(ctx: Any, instance_id: str) -> None:
    rds = ctx.client("rds")
    try:
        rds.delete_db_instance(DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBInstanceNotFound":
            raise


def _delete_snapshot(ctx: Any, snapshot_id: str) -> None:
    rds = ctx.client("rds")
    try:
        rds.delete_db_snapshot(DBSnapshotIdentifier=snapshot_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBSnapshotNotFound":
            raise


def _cancel_export_quietly(ctx: Any, export_id: str) -> None:
    rds = ctx.client("rds")
    try:
        rds.cancel_export_task(ExportTaskIdentifier=export_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExportTaskNotFound":
            raise


def _poll_until_terminal(
    ctx: Any, export_id: str, timeout_s: float, interval_s: float
) -> tuple[str, str | None]:
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    last_status, last_cause = "UNKNOWN", None
    terminal = {"COMPLETE", "FAILED", "CANCELED"}
    while time.monotonic() < deadline:
        task = rds.describe_export_tasks(ExportTaskIdentifier=export_id)["ExportTasks"][0]
        last_status, last_cause = task["Status"], task.get("FailureCause")
        if last_status in terminal:
            return last_status, last_cause
        time.sleep(interval_s)
    raise AssertionError(
        f"export task {export_id} did not reach a terminal status within {timeout_s}s "
        f"(last={last_status})"
    )


def _poll_until_not_starting(
    ctx: Any, export_id: str, timeout_s: float, interval_s: float
) -> tuple[str, str | None]:
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    last_status, last_cause = "UNKNOWN", None
    while time.monotonic() < deadline:
        task = rds.describe_export_tasks(ExportTaskIdentifier=export_id)["ExportTasks"][0]
        last_status, last_cause = task["Status"], task.get("FailureCause")
        if last_status != "STARTING":
            return last_status, last_cause
        time.sleep(interval_s)
    raise AssertionError(
        f"export task {export_id} with a trusted role did not progress past STARTING "
        f"within {timeout_s}s (last={last_status!r}, cause={last_cause!r})"
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
