"""op-contract-import-image."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "op-contract-import-image"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ImportImage: a disposable vmimport-capable role plus a real S3-backed disk creates a
    describable task, and CancelImportTask rejects a bogus id."""
    ec2 = ctx.client("ec2")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    bucket = _create_bucket(ctx, s3)
    key = "sim2real-disk.raw"
    body = (b"sim2real-behavioral-fixture-" + ctx.unique_name("").encode()) * 64
    s3.put_object(Bucket=bucket, Key=key, Body=body)

    # VM Import/Export needs an IAM role vmie.amazonaws.com can assume; a bare sandbox account has
    # no such role. ImportImage accepts a custom RoleName, so create a disposable one for this run
    # rather than assuming a pre-existing "vmimport" role that may not exist.
    role_name = _ensure_vmimport_role(ctx, iam)

    resp = _call_with_role_propagation(
        lambda: ec2.import_image(
            Description=ctx.unique_name("sim2real-import-image-"),
            DiskContainers=[
                {
                    "Description": "sim2real-disk",
                    "Format": "RAW",
                    "UserBucket": {"S3Bucket": bucket, "S3Key": key},
                }
            ],
            RoleName=role_name,
        )
    )

    task_id = resp["ImportTaskId"]
    assert resp.get("Status"), "expected a non-empty initial import task status"
    ctx.on_cleanup(lambda: _best_effort_cancel_import(ec2, task_id))

    described = ec2.describe_import_image_tasks(ImportTaskIds=[task_id])["ImportImageTasks"]
    assert described and described[0]["ImportTaskId"] == task_id

    bogus_task_id = "import-ami-ffffffffffffffffff"
    code, message = _error(lambda: ec2.cancel_import_task(ImportTaskId=bogus_task_id))
    # ImportImage/ImportSnapshot tasks are implemented on the same conversion-task machinery as
    # the legacy import-instance/import-volume APIs, so there is no dedicated "not found" family
    # for a bogus import task id -- real AWS answers InvalidConversionTaskId.
    assert code == "InvalidConversionTaskId", f"unexpected error code {code!r}"
    expected = f"The import-image-task ID '{bogus_task_id}' does not exist"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _create_bucket(ctx, s3) -> str:
    bucket = ctx.unique_name("sim2real-import-image-").lower().replace("_", "-")
    region = ctx.region
    if region == "us-east-1":
        # S3's CreateBucket rejects an explicit LocationConstraint of "us-east-1" -- the region
        # must be omitted there and supplied everywhere else. Not a region pin on the resource.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    return bucket


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    try:
        objects = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for obj in objects:
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    finally:
        s3.delete_bucket(Bucket=bucket)


def _best_effort_cancel_import(ec2, task_id: str) -> None:
    try:
        ec2.cancel_import_task(ImportTaskId=task_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidConversionTaskId":
            raise


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises
    AssertionError: a target that accepts what AWS refuses fails loudly here."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _ensure_vmimport_role(ctx, iam) -> str:
    """Create (and register cleanup for) a disposable IAM role that vmie.amazonaws.com can
    assume, with the S3/EC2 permissions VM Import/Export needs. ImportImage accepts a custom
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


def _is_role_propagation_error(exc: ClientError) -> bool:
    code = exc.response["Error"]["Code"]
    msg = exc.response["Error"].get("Message", "")
    return code == "InvalidParameter" and "vmimport" in msg.lower()


def _call_with_role_propagation(fn, timeout_s: float = 120.0, interval_s: float = 5.0):
    """VM Import/Export validates the service role via IAM, which is eventually consistent after
    CreateRole/PutRolePolicy -- retry past the propagation window instead of failing on a role AWS
    just hasn't finished replicating yet."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if _is_role_propagation_error(exc) and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
