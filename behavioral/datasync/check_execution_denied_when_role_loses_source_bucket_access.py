"""execution-denied-when-role-loses-source-bucket-access."""
from __future__ import annotations

import concurrent.futures
import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "execution-denied-when-role-loses-source-bucket-access"
GROUP = "data-transfer"
SERVICES = ["datasync"]

_OBJECTS = {
    "alpha.txt": b"A" * 100,
    "beta.txt": b"B" * 250,
    "logs/gamma.log": b"C" * 500,
}
_TOTAL_BYTES = sum(len(b) for b in _OBJECTS.values())


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """After its role loses S3 access, a task still starts but its execution ends ERROR in the prepare phase with
    ErrorCode FsS3UnableToConnectToEndpoint, transfer PENDING, nothing transferred or landed, while an
    identical task with access succeeds and copies every byte."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    source = _create_bucket(ctx, "sim2real-ds-src-")
    denied_dest = _create_bucket(ctx, "sim2real-ds-denied-")
    allowed_dest = _create_bucket(ctx, "sim2real-ds-allowed-")
    for key, body in _OBJECTS.items():
        s3.put_object(Bucket=source, Key=key, Body=body)

    # Two roles so that revoking one leaves the positive control's credentials untouched.
    revoked_role, revoked_arn = _create_datasync_role(ctx, [source, denied_dest])
    _intact_role, intact_arn = _create_datasync_role(ctx, [source, allowed_dest])

    denied_source_loc = _create_s3_location(ctx, source, revoked_arn)
    denied_dest_loc = _create_s3_location(ctx, denied_dest, revoked_arn)
    allowed_source_loc = _create_s3_location(ctx, source, intact_arn)
    allowed_dest_loc = _create_s3_location(ctx, allowed_dest, intact_arn)

    denied_task = _create_task(ctx, denied_source_loc, denied_dest_loc)
    allowed_task = _create_task(ctx, allowed_source_loc, allowed_dest_loc)

    # Break exactly one thing: the denied task's role loses every S3 permission it had.
    iam.delete_role_policy(RoleName=revoked_role, PolicyName="datasync-s3")
    remaining = iam.list_role_policies(RoleName=revoked_role).get("PolicyNames", [])
    assert remaining == [], f"revoked role still carries inline policies {remaining!r}"

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        denied_future = pool.submit(_run_execution, ctx, denied_task)
        allowed_future = pool.submit(_run_execution, ctx, allowed_task)
        _denied_arn, denied_exec = denied_future.result()
        _allowed_arn, allowed_exec = allowed_future.result()

    # The denial.
    assert denied_exec["Status"] == "ERROR", (
        f"execution with no bucket access ended {denied_exec['Status']!r}, expected ERROR "
        f"(result {json.dumps(denied_exec.get('Result', {}), default=str)})"
    )
    denied_result = denied_exec["Result"]
    assert denied_result["PrepareStatus"] == "ERROR", (
        f"prepare phase was {denied_result['PrepareStatus']!r}, expected ERROR — the denial lands before transfer"
    )
    assert denied_result["ErrorCode"] == "FsS3UnableToConnectToEndpoint", (
        f"error code was {denied_result.get('ErrorCode')!r} ({denied_result.get('ErrorDetail')!r})"
    )
    assert denied_result["TransferStatus"] == "PENDING", (
        f"transfer phase was {denied_result['TransferStatus']!r}, expected PENDING — it must never start"
    )

    # The effect is absent: nothing was read out of the source or written to the destination.
    assert denied_exec["FilesTransferred"] == 0, (
        f"FilesTransferred was {denied_exec['FilesTransferred']!r}, expected 0"
    )
    assert denied_exec["BytesTransferred"] == 0, (
        f"BytesTransferred was {denied_exec['BytesTransferred']!r}, expected 0"
    )
    denied_landed = _bucket_sizes(ctx, denied_dest)
    assert denied_landed == {}, (
        f"destination of the denied task holds {denied_landed!r}; it must be empty"
    )

    # The task itself survives the failed execution — the failure is the execution's, not the task's.
    described = ctx.client("datasync").describe_task(TaskArn=denied_task)
    assert described["Status"] == "AVAILABLE", (
        f"task status after the failed execution was {described['Status']!r}, expected AVAILABLE"
    )

    # Positive control: the identically-shaped task whose role kept its policy transfers everything.
    assert allowed_exec["Status"] == "SUCCESS", (
        f"the intact-role execution ended {allowed_exec['Status']!r}, expected SUCCESS "
        f"(result {json.dumps(allowed_exec.get('Result', {}), default=str)})"
    )
    assert allowed_exec["BytesTransferred"] == _TOTAL_BYTES, (
        f"the intact-role execution transferred {allowed_exec['BytesTransferred']!r} bytes, expected {_TOTAL_BYTES}"
    )
    allowed_landed = _bucket_sizes(ctx, allowed_dest)
    expected = {k: len(v) for k, v in _OBJECTS.items()}
    assert allowed_landed == expected, (
        f"the intact-role destination holds {allowed_landed!r}, expected {expected!r}"
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
        Options={"VerifyMode": "POINT_IN_TIME_CONSISTENT", "LogLevel": "OFF", "TransferMode": "ALL", **options},
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


def _bucket_sizes(ctx, bucket: str) -> dict:
    s3 = ctx.client("s3")
    sizes = {}
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            sizes[obj["Key"]] = obj["Size"]
    return sizes


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
