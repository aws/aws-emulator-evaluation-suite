"""op-contract-cancel-import-task."""
from __future__ import annotations

from typing import Any, Callable
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-cancel-import-task"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CancelImportTask cancels an in-progress import-snapshot task, which then reports a cancelling,
    cancelled, deleting or deleted status; a well-formed import task ID that does not exist fails with
    InvalidConversionTaskId and its exact message."""
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    bucket = _create_bucket(ctx, ec2, s3)
    key = "disk.vmdk"
    s3.put_object(Bucket=bucket, Key=key, Body=b"sim2real-cancel-import-task-probe")

    role_name = _ensure_vmimport_role(ctx, iam)

    resp = _call_with_role_propagation(
        lambda: ec2.import_snapshot(
            Description="sim2real-cancel-import-task-contract",
            DiskContainer={"Format": "VMDK", "UserBucket": {"S3Bucket": bucket, "S3Key": key}},
            RoleName=role_name,
            TagSpecifications=[
                {
                    "ResourceType": "import-snapshot-task",
                    "Tags": [{"Key": "sim2real-check", "Value": CHECK}],
                }
            ],
        )
    )
    task_id = resp["ImportTaskId"]
    ctx.on_cleanup(lambda: _best_effort_cancel(ec2, task_id))

    # --- positive control: CancelImportTask succeeds against a real, in-progress task ---
    cancel_resp = ec2.cancel_import_task(ImportTaskId=task_id)
    assert cancel_resp.get("ImportTaskId") == task_id, (
        f"expected CancelImportTask to echo {task_id!r}, got {cancel_resp.get('ImportTaskId')!r}"
    )

    described = _poll_until(
        lambda: ec2.describe_import_snapshot_tasks(ImportTaskIds=[task_id])[
            "ImportSnapshotTasks"
        ][0],
        lambda t: t.get("SnapshotTaskDetail", {}).get("Status")
        in {"cancelling", "cancelled", "deleted", "deleting", "completed"},
        timeout_s=90.0,
        interval_s=3.0,
    )
    status = described["SnapshotTaskDetail"]["Status"]
    assert status in {"cancelling", "cancelled", "deleted", "deleting"}, (
        f"expected a cancelled-family status after CancelImportTask, got {status!r}"
    )

    # --- negative: a well-formed but nonexistent import task id is rejected ---
    code, code_message = _error_code(
        lambda: ec2.cancel_import_task(ImportTaskId="import-ami-0123456789abcdef0")
    )
    assert code == "InvalidConversionTaskId", f"expected InvalidConversionTaskId, got {code}"
    expected_code_message = "The import-image-task ID 'import-ami-0123456789abcdef0' does not exist"
    assert code_message == expected_code_message, f"expected message {expected_code_message!r}, got {code_message!r}"


def _error_code(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except Exception as exc:
        err = getattr(exc, "response", {}).get("Error")
        if not err:
            raise
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _is_role_propagation_error(exc) -> bool:
    code = exc.response["Error"]["Code"]
    msg = exc.response["Error"].get("Message", "")
    return code == "InvalidParameter" and "vmimport" in msg.lower()


def _call_with_role_propagation(fn, timeout_s=120.0, interval_s=5.0):
    """VM Import/Export validates the service role via IAM, which is eventually consistent
    after CreateRole/PutRolePolicy -- retry past the propagation window instead of failing on a
    role that AWS just hasn't finished replicating yet."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as e:
            if _is_role_propagation_error(e) and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _ensure_vmimport_role(ctx, iam) -> str:
    """Create (and register cleanup for) a disposable IAM role that vmie.amazonaws.com can
    assume, with the S3/EC2 permissions VM Import/Export needs. ImportSnapshot accepts a custom
    RoleName, so a fresh, unique role avoids clashing with any pre-existing "vmimport" role."""
    role_name = ctx.unique_name("sim2real-vmimport-")

    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "vmie.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"sts:Externalid": "vmimport"}},
            }
        ],
    }
    permission_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetBucketLocation",
                    "s3:GetObject",
                    "s3:ListBucket",
                    "s3:PutObject",
                    "s3:GetBucketAcl",
                ],
                "Resource": ["arn:aws:s3:::*"],
            },
            {
                "Effect": "Allow",
                "Action": [
                    "ec2:ModifySnapshotAttribute",
                    "ec2:CopySnapshot",
                    "ec2:RegisterImage",
                    "ec2:Describe*",
                ],
                "Resource": "*",
            },
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Description="sim2real behavioral check: disposable VM Import/Export role",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )

    def _cleanup_role() -> None:
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-vmimport-policy")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup_role)
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sim2real-vmimport-policy",
        PolicyDocument=json.dumps(permission_policy),
    )
    return role_name


def _create_bucket(ctx, ec2, s3) -> str:
    bucket = ctx.unique_name("sim2real-cancelimport-").lower().replace("_", "-")
    region = ec2.meta.region_name
    if region and region != "us-east-1":
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    else:
        s3.create_bucket(Bucket=bucket)
    waiter = s3.get_waiter("bucket_exists")
    waiter.wait(Bucket=bucket, WaiterConfig={"Delay": 2, "MaxAttempts": 50})
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    return bucket


def _delete_bucket(s3, bucket: str) -> None:
    try:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for obj in objs:
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _best_effort_cancel(ec2, task_id: str) -> None:
    try:
        ec2.cancel_import_task(ImportTaskId=task_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidConversionTaskId":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
