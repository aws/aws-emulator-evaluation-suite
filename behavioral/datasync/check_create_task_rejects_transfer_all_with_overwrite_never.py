"""create-task-rejects-transfer-all-with-overwrite-never."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-task-rejects-transfer-all-with-overwrite-never"
GROUP = "option-validation"
SERVICES = ["datasync"]


@tags("axis:rejection", "concern:negative-classes", "cap:c1", "plane:control")
def run(ctx) -> None:
    """CreateTask with TransferMode ALL plus OverwriteMode NEVER fails with InvalidRequestException and its exact
    message, while CHANGED+NEVER and ALL+ALWAYS on the same locations are created: the model allows each
    option, the service refuses the pair, and no task is left from the refusal."""
    ds = ctx.client("datasync")

    source = _create_bucket(ctx, "sim2real-ds-src-")
    dest = _create_bucket(ctx, "sim2real-ds-dst-")
    _role_name, role_arn = _create_datasync_role(ctx, [source, dest])
    source_loc = _create_s3_location(ctx, source, role_arn)
    dest_loc = _create_s3_location(ctx, dest, role_arn)

    refused_name = ctx.unique_name("sim2real-ds-refused-")
    code, message = _error(
        lambda: ds.create_task(
            SourceLocationArn=source_loc,
            DestinationLocationArn=dest_loc,
            Name=refused_name,
            Options={
                "VerifyMode": "POINT_IN_TIME_CONSISTENT",
                "LogLevel": "OFF",
                "TransferMode": "ALL",
                "OverwriteMode": "NEVER",
            },
        )
    )
    assert code == "InvalidRequestException", (
        f"CreateTask with TransferMode=ALL + OverwriteMode=NEVER failed with {code!r}, "
        "expected 'InvalidRequestException'"
    )
    expected_message = "Invalid SyncOption value. Option: TransferMode,OverwriteMode, Value: ALL,NEVER."
    assert message == expected_message, (
        f"CreateTask with TransferMode=ALL + OverwriteMode=NEVER said {message!r}, expected {expected_message!r}"
    )

    # Positive control 1: OverwriteMode NEVER on its own is accepted.
    never_task, never_name = _create_task(
        ctx, source_loc, dest_loc, TransferMode="CHANGED", OverwriteMode="NEVER"
    )
    never_options = ds.describe_task(TaskArn=never_task)["Options"]
    assert never_options["TransferMode"] == "CHANGED", (
        f"accepted task reports TransferMode {never_options['TransferMode']!r}, expected CHANGED"
    )
    assert never_options["OverwriteMode"] == "NEVER", (
        f"accepted task reports OverwriteMode {never_options['OverwriteMode']!r}, expected NEVER"
    )

    # Positive control 2: TransferMode ALL on its own is accepted.
    all_task, all_name = _create_task(
        ctx, source_loc, dest_loc, TransferMode="ALL", OverwriteMode="ALWAYS"
    )
    all_options = ds.describe_task(TaskArn=all_task)["Options"]
    assert all_options["TransferMode"] == "ALL", (
        f"accepted task reports TransferMode {all_options['TransferMode']!r}, expected ALL"
    )
    assert all_options["OverwriteMode"] == "ALWAYS", (
        f"accepted task reports OverwriteMode {all_options['OverwriteMode']!r}, expected ALWAYS"
    )

    # The effect is absent: the refused call left no task, while both controls are listed.
    # Only names this check minted are considered, so a sibling run cannot change the answer.
    wanted = {refused_name, never_name, all_name}
    found = {t["Name"]: t["TaskArn"] for t in _list_tasks(ctx) if t.get("Name") in wanted}
    assert found == {never_name: never_task, all_name: all_task}, (
        f"ListTasks reports {json.dumps(found)} for this check's task names; the refused "
        f"{refused_name!r} must not exist and both controls must"
    )


def _error(fn) -> tuple:
    """Return the (code, message) of the AWS error ``fn`` raises; raise if the call succeeds."""
    try:
        fn()
    except Exception as exc:
        error = getattr(exc, "response", {}).get("Error", {})
        code = error.get("Code")
        if code is None:
            raise AssertionError(f"exception carried no AWS error code: {exc!r}") from exc
        return code, error.get("Message")
    raise AssertionError("the call succeeded; real AWS rejects it, so there is no error code to read")


def _create_bucket(ctx, prefix: str) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name(prefix)
    # us-east-1 is the one region S3 rejects an explicit LocationConstraint for.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda b=bucket: _empty_and_delete_bucket(ctx, b))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": bucket}]})
    return bucket


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_datasync_role(ctx, buckets: list) -> tuple:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ds-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "datasync.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": role_name}],
    )
    ctx.on_cleanup(lambda rn=role_name: _delete_role(ctx, rn))
    resources = []
    for bucket in buckets:
        resources += [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetBucketLocation",
                    "s3:ListBucket",
                    "s3:ListBucketMultipartUploads",
                    "s3:GetObject",
                    "s3:PutObject",
                    "s3:AbortMultipartUpload",
                    "s3:DeleteObject",
                    "s3:GetObjectTagging",
                    "s3:PutObjectTagging",
                ],
                "Resource": resources,
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="datasync-s3", PolicyDocument=json.dumps(policy))
    return role_name, role["Role"]["Arn"]


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        for name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_s3_location(ctx, bucket: str, role_arn: str) -> str:
    """CreateLocationS3 runs an access test as the role, so it fails until IAM has propagated.

    No API reports a role as effective, so the bounded retry at first use IS the wait.
    """
    ds = ctx.client("datasync")
    deadline = time.monotonic() + 180.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = ds.create_location_s3(
                S3BucketArn=f"arn:aws:s3:::{bucket}",
                Subdirectory="/",
                S3Config={"BucketAccessRoleArn": role_arn},
                Tags=[{"Key": "sim2real", "Value": bucket}],
            )["LocationArn"]
            ctx.on_cleanup(lambda a=arn: ds.delete_location(LocationArn=a))
            return arn
        except Exception as exc:
            last = exc
            time.sleep(5)
    raise AssertionError(f"CreateLocationS3 never succeeded for {bucket!r} within 180s: {last!r}")


def _create_task(ctx, source_loc: str, dest_loc: str, **options) -> tuple:
    ds = ctx.client("datasync")
    name = ctx.unique_name("sim2real-ds-task-")
    task = ds.create_task(
        SourceLocationArn=source_loc,
        DestinationLocationArn=dest_loc,
        Name=name,
        Options={"VerifyMode": "POINT_IN_TIME_CONSISTENT", "LogLevel": "OFF", **options},
        Tags=[{"Key": "sim2real", "Value": name}],
    )["TaskArn"]
    ctx.on_cleanup(lambda t=task: ds.delete_task(TaskArn=t))
    deadline = time.monotonic() + 120.0
    described = ds.describe_task(TaskArn=task)
    while time.monotonic() < deadline:
        if described["Status"] != "CREATING":
            break
        time.sleep(3)
        described = ds.describe_task(TaskArn=task)
    assert described["Status"] == "AVAILABLE", (
        f"task {name!r} settled at {described['Status']!r}, expected AVAILABLE"
    )
    return task, name


def _list_tasks(ctx) -> list:
    ds = ctx.client("datasync")
    out = []
    for page in ds.get_paginator("list_tasks").paginate():
        out.extend(page.get("Tasks", []))
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
