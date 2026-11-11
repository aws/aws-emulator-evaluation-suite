"""rds-export-task-bucket-policy-deny-negative."""
from __future__ import annotations

import json
import time
import uuid
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rds-export-task-bucket-policy-deny-negative"
GROUP = "permission-boundary"
SERVICES = ["rds", "s3"]

FULL_S3_ACTIONS = [
    "s3:PutObject*",
    "s3:GetObject*",
    "s3:ListBucket",
    "s3:DeleteObject*",
    "s3:GetBucketLocation",
]


@tags(
    "axis:rejection",
    "cap:c4",
    "cap:c7",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A bucket-policy Deny of the export role's PutObject makes StartExportTask fail at once with
    IamRoleMissingPermissions despite a correct role, trust and KMS grant, creating no task and writing
    nothing; with the Deny lifted the identical call succeeds."""
    bucket = _create_bucket(ctx)
    kms_key_arn = _create_kms_key(ctx)
    snapshot_arn = _create_snapshot_source(ctx)
    rds = ctx.client("rds")
    s3 = ctx.client("s3")

    # Role is fully correct: trust + S3 write actions + KMS grant/describe.
    role_arn = _create_export_role(
        ctx, "export.rds.amazonaws.com", bucket, kms_key_arn, FULL_S3_ACTIONS
    )

    # Break exactly one thing: an explicit bucket-policy Deny for this role's PutObject,
    # overriding its otherwise-correct identity-based permissions.
    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyExportRolePut",
                "Effect": "Deny",
                "Principal": {"AWS": role_arn},
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket}/*",
            }
        ],
    }
    _put_bucket_policy_with_retry(s3, bucket, deny_policy)
    ctx.on_cleanup(lambda: s3.delete_bucket_policy(Bucket=bucket))

    # RDS validates the role's effective S3 access (IAM + bucket policy) synchronously
    # before it ever creates the export task, so the bucket-policy Deny surfaces as a
    # ClientError on the StartExportTask call itself, not an async FAILED status.
    denied_export_id = ctx.unique_name("sim2real-export-denied-")
    error = _client_error(
        lambda: rds.start_export_task(
            ExportTaskIdentifier=denied_export_id,
            SourceArn=snapshot_arn,
            S3BucketName=bucket,
            IamRoleArn=role_arn,
            KmsKeyId=kms_key_arn,
        )
    )
    ctx.on_cleanup(lambda: _cancel_export_task_ignore(rds, denied_export_id))
    assert error.get("Code") == "IamRoleMissingPermissions", (
        f"expected IamRoleMissingPermissions with a bucket-policy Deny in place, got {error}"
    )
    expected_message = (
        f"The IAM role {role_arn} isn't authorized to call s3:PutObject on the S3 bucket {bucket}."
    )
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )
    _assert_no_export_task(rds, denied_export_id)
    denied_listing = s3.list_objects_v2(Bucket=bucket, Prefix=denied_export_id)
    assert "Contents" not in denied_listing, (
        f"objects appeared despite the bucket-policy Deny blocking the call: {denied_listing.get('Contents')}"
    )

    # Restore: remove the Deny, everything else held constant -- the identical call must
    # succeed.
    s3.delete_bucket_policy(Bucket=bucket)
    after_export_id = ctx.unique_name("sim2real-export-after-")
    _start_export_task_with_retry(
        rds,
        ExportTaskIdentifier=after_export_id,
        SourceArn=snapshot_arn,
        S3BucketName=bucket,
        IamRoleArn=role_arn,
        KmsKeyId=kms_key_arn,
    )
    ctx.on_cleanup(lambda: _cancel_export_task_ignore(rds, after_export_id))
    after_final = _wait_export_task(rds, after_export_id, timeout_s=2700, interval_s=20)
    assert after_final["Status"] == "COMPLETE", (
        f"restored export did not complete: status={after_final['Status']} "
        f"cause={after_final.get('FailureCause')}"
    )
    assert "Contents" in s3.list_objects_v2(Bucket=bucket, Prefix=after_export_id), (
        "restored export produced no S3 objects"
    )


def _put_bucket_policy_with_retry(s3, bucket, policy_doc, timeout_s=60.0):
    """put_bucket_policy referencing a just-created IAM role ARN as Principal can transiently
    fail with MalformedPolicy/"Invalid principal in policy" until the new role propagates through
    IAM -- retry until it resolves."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy_doc))
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            msg = err.response["Error"].get("Message", "")
            if (
                code == "MalformedPolicy"
                and "principal" in msg.lower()
                and time.monotonic() < deadline
            ):
                time.sleep(5)
                continue
            raise


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
        Tags=[{"TagKey": "sim2real", "TagValue": "true"}],
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
        Tags=[{"Key": "sim2real", "Value": "true"}],
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
        Tags=[{"Key": "sim2real", "Value": "true"}],
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
    rds.create_db_snapshot(DBSnapshotIdentifier=snap_id, DBInstanceIdentifier=db_id)
    ctx.on_cleanup(lambda: rds.delete_db_snapshot(DBSnapshotIdentifier=snap_id))
    final = _poll_until(
        lambda: rds.describe_db_snapshots(DBSnapshotIdentifier=snap_id)["DBSnapshots"][0],
        lambda snap: snap["Status"] == "available",
        timeout_s=1200,
        interval_s=15,
        description=f"snapshot {snap_id} available",
    )
    return final["DBSnapshotArn"]


def _start_export_task_with_retry(rds, timeout_s=90.0, **kwargs):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return rds.start_export_task(**kwargs)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if (
                code in ("IamRoleMissingPermissions", "AccessDenied", "KMSKeyNotAccessibleFault")
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


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because a target
    that ACCEPTS a call AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _assert_no_export_task(rds, export_task_id) -> None:
    """describe_export_tasks filtered by a never-created ExportTaskIdentifier returns an
    empty list rather than raising ExportTaskNotFound."""
    found = rds.describe_export_tasks(ExportTaskIdentifier=export_task_id)["ExportTasks"]
    assert found == [], f"expected no export task to exist for {export_task_id}, found {found!r}"


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
