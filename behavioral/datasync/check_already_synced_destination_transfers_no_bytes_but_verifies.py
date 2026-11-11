"""already-synced-destination-transfers-no-bytes-but-verifies."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "already-synced-destination-transfers-no-bytes-but-verifies"
GROUP = "data-transfer"
SERVICES = ["datasync"]

_OBJECTS = {
    "alpha.txt": b"A" * 100,
    "beta.txt": b"B" * 250,
    "logs/gamma.log": b"C" * 500,
}


@tags("concern:data-plane", "dp:api", "plane:data", "axis:happy-path", "cap:c1")
def run(ctx) -> None:
    """A CHANGED-mode execution over an identical destination succeeds with verification SUCCESS, 0 bytes
    written and transferred, every file skipped and verified, and each destination object's ETag and
    LastModified unchanged: an up-to-date destination is verified, not rewritten."""
    s3 = ctx.client("s3")

    source = _create_bucket(ctx, "sim2real-ds-src-")
    dest = _create_bucket(ctx, "sim2real-ds-dst-")
    for key, body in _OBJECTS.items():
        s3.put_object(Bucket=source, Key=key, Body=body)
        # Seed the destination with byte-identical content, written by S3 and not by DataSync.
        s3.put_object(Bucket=dest, Key=key, Body=body)

    before = _bucket_state(ctx, dest)
    assert set(before) == set(_OBJECTS), (
        f"destination seed landed {sorted(before)!r}, expected {sorted(_OBJECTS)!r}"
    )

    _role_name, role_arn = _create_datasync_role(ctx, [source, dest])
    source_loc = _create_s3_location(ctx, source, role_arn)
    dest_loc = _create_s3_location(ctx, dest, role_arn)
    task = _create_task(ctx, source_loc, dest_loc, TransferMode="CHANGED")

    _execution_arn, execution = _run_execution(ctx, task)
    assert execution["Status"] == "SUCCESS", (
        f"execution ended {execution['Status']!r} (result {json.dumps(execution.get('Result', {}), default=str)})"
    )
    result = execution["Result"]
    assert result["VerifyStatus"] == "SUCCESS", f"verify phase was {result['VerifyStatus']!r}"
    assert execution["FilesVerified"] == len(_OBJECTS), (
        f"FilesVerified was {execution['FilesVerified']!r}, expected {len(_OBJECTS)} — verification must still run"
    )

    assert execution["BytesWritten"] == 0, (
        f"BytesWritten was {execution['BytesWritten']!r}; an already-identical destination must be written 0 bytes"
    )
    assert execution["BytesTransferred"] == 0, (
        f"BytesTransferred was {execution['BytesTransferred']!r}; nothing needed transferring"
    )
    # The prepare phase's own diff decides there is nothing to move, and every file is accounted
    # for as skipped rather than transferred.
    assert execution["EstimatedFilesToTransfer"] == 0, (
        f"EstimatedFilesToTransfer was {execution['EstimatedFilesToTransfer']!r}; the prepare phase "
        "must find nothing to move"
    )
    assert execution["EstimatedBytesToTransfer"] == 0, (
        f"EstimatedBytesToTransfer was {execution['EstimatedBytesToTransfer']!r}, expected 0"
    )
    assert execution["FilesTransferred"] == 0, (
        f"FilesTransferred was {execution['FilesTransferred']!r}, expected 0"
    )
    assert execution["FilesSkipped"] == len(_OBJECTS), (
        f"FilesSkipped was {execution['FilesSkipped']!r}, expected all {len(_OBJECTS)} to be skipped"
    )
    assert execution["FilesDeleted"] == 0, (
        f"FilesDeleted was {execution['FilesDeleted']!r}; a verify-only pass must delete nothing"
    )

    after = _bucket_state(ctx, dest)
    assert after == before, (
        f"destination objects changed across the execution: before {before!r}, after {after!r}"
    )
    for key, body in _OBJECTS.items():
        got = s3.get_object(Bucket=dest, Key=key)["Body"].read()
        assert got == body, (
            f"destination object {key!r} is now {len(got)} bytes, expected the untouched {len(body)}"
        )


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


def _create_task(ctx, source_loc: str, dest_loc: str, **options) -> str:
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
    return task


def _run_execution(ctx, task_arn: str, timeout_s: float = 600.0, **start_kwargs) -> tuple:
    ds = ctx.client("datasync")
    execution_arn = ds.start_task_execution(TaskArn=task_arn, **start_kwargs)["TaskExecutionArn"]
    deadline = time.monotonic() + timeout_s
    execution = ds.describe_task_execution(TaskExecutionArn=execution_arn)
    while time.monotonic() < deadline:
        if execution["Status"] in ("SUCCESS", "ERROR"):
            return execution_arn, execution
        time.sleep(5)
        execution = ds.describe_task_execution(TaskExecutionArn=execution_arn)
    raise AssertionError(
        f"execution {execution_arn} never reached a terminal status within {timeout_s}s; "
        f"last status {execution['Status']!r}"
    )


def _bucket_state(ctx, bucket: str) -> dict:
    """Key -> (size, etag, last-modified): the three things a rewrite would change."""
    s3 = ctx.client("s3")
    state = {}
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            state[obj["Key"]] = (obj["Size"], obj["ETag"], obj["LastModified"].isoformat())
    return state


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
