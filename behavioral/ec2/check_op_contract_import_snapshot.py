"""op-contract-import-snapshot."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-import-snapshot"
GROUP = "error-semantics"
SERVICES = ["ec2"]


_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ImportSnapshot accepts a request and creates a trackable task; DryRun rejects without side effects."""
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-importsnap-")

    # ImportSnapshot validates that the referenced S3 bucket/object actually exist (even for the
    # real call after DryRun) — it does not accept an arbitrary, never-created bucket name.
    # Create a disposable bucket with a placeholder object for the disk container to reference.
    _create_bucket(ec2, s3, bucket)
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    s3.put_object(Bucket=bucket, Key="disk.vmdk", Body=b"sim2real-import-snapshot-probe")

    # VM Import/Export requires an IAM role (named via RoleName, default "vmimport") that
    # vmie.amazonaws.com can assume. A bare sandbox account has no such role, so
    # ImportSnapshot fails with InvalidParameter ("service role ... does not exist") rather than
    # DryRunOperation/success — create a disposable one for this check and give IAM's eventual
    # consistency time to propagate before relying on it.
    role_name = _ensure_vmimport_role(ctx, iam)

    # --- error boundary: DryRun must reject before any task is created ---
    code, message = _error_with_role_propagation(
        lambda: ec2.import_snapshot(
            DryRun=True,
            Description="sim2real dry-run probe",
            DiskContainer={
                "Format": "VMDK",
                "UserBucket": {"S3Bucket": bucket, "S3Key": "disk.vmdk"},
            },
            RoleName=role_name,
        )
    )
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    assert message == _DRY_RUN_MESSAGE, f"unexpected DryRunOperation message: {message!r}"

    # --- success path: the call is accepted and returns a well-formed, trackable task ---
    resp = _call_with_role_propagation(
        lambda: ec2.import_snapshot(
            Description="sim2real-import-snapshot-contract",
            DiskContainer={
                "Format": "VMDK",
                "UserBucket": {"S3Bucket": bucket, "S3Key": "disk.vmdk"},
            },
            RoleName=role_name,
            TagSpecifications=[
                {"ResourceType": "import-snapshot-task", "Tags": [{"Key": "Name", "Value": bucket}]}
            ],
        )
    )
    task_id = resp["ImportTaskId"]
    assert task_id.startswith("import-snap-"), f"unexpected task id format: {task_id!r}"
    ctx.on_cleanup(lambda: _cancel_import_snapshot(ec2, task_id))

    detail = resp.get("SnapshotTaskDetail")
    assert detail is not None, "ImportSnapshot response missing SnapshotTaskDetail"

    # The task must be independently discoverable via DescribeImportSnapshotTasks.
    described = _poll_until(
        lambda: ec2.describe_import_snapshot_tasks(ImportTaskIds=[task_id])[
            "ImportSnapshotTasks"
        ][0],
        lambda t: t.get("SnapshotTaskDetail", {}).get("Status") is not None,
        timeout_s=30.0,
        interval_s=2.0,
    )
    described_tags = {t["Key"]: t["Value"] for t in described.get("Tags", [])}
    assert described_tags.get("Name") == bucket, (
        f"expected TagSpecifications' Name={bucket!r} to round-trip, got {described_tags!r}"
    )

    status = described["SnapshotTaskDetail"]["Status"]
    assert status in {
        "active",
        "pending",
        "cancelling",
        "cancelled",
        "completed",
        "deleted",
        "deleting",
    }, f"unexpected task status: {status!r}"


def _is_role_propagation_error(exc) -> bool:
    code = exc.response["Error"]["Code"]
    msg = exc.response["Error"].get("Message", "")
    return code == "InvalidParameter" and "vmimport" in msg.lower()


def _call_with_role_propagation(fn, timeout_s=120.0, interval_s=5.0):
    """VM Import/Export validates the service role via IAM, which is eventually consistent
    after CreateRole/PutRolePolicy — retry past the propagation window instead of failing on a
    role that AWS just hasn't finished replicating yet."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as e:
            if _is_role_propagation_error(e) and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _error_with_role_propagation(fn, timeout_s=120.0, interval_s=5.0):
    """Call fn(); return the (code, message) of the ClientError it raises, retrying a transient
    "service role does not exist" InvalidParameter (IAM propagation lag) rather than taking it
    as the boundary's answer. A success raises AssertionError: a target that accepts what AWS
    refuses fails loudly here."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as e:
            if _is_role_propagation_error(e) and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
        raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _ensure_vmimport_role(ctx, iam, role_name: str | None = None) -> str:
    """Create (and register cleanup for) a disposable IAM role that vmie.amazonaws.com can
    assume, with the S3/EC2 permissions VM Import/Export needs. ImportSnapshot accepts a custom
    RoleName, so a fresh, unique role avoids clashing with any pre-existing "vmimport" role."""
    import json

    if role_name is None:
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
        Tags=[{"Key": "Name", "Value": role_name}],
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


def _create_bucket(ec2, s3, bucket: str) -> None:
    region = ec2.meta.region_name
    kwargs = {"Bucket": bucket}
    # us-east-1 is S3's own API special case: CreateBucketConfiguration must be omitted
    # there and supplied everywhere else, regardless of which region this check runs in.
    if region and region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
    s3.create_bucket(**kwargs)
    waiter = s3.get_waiter("bucket_exists")
    waiter.wait(Bucket=bucket, WaiterConfig={"Delay": 2, "MaxAttempts": 50})


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
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _cancel_import_snapshot(ec2, task_id: str) -> None:
    try:
        ec2.cancel_import_task(ImportTaskId=task_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidConversionTaskId":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
