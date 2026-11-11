"""overwrite-mode-never-preserves-existing-destination-objects."""
from __future__ import annotations

import concurrent.futures
import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "overwrite-mode-never-preserves-existing-destination-objects"
GROUP = "data-transfer"
SERVICES = ["datasync"]

_OBJECTS = {
    "alpha.txt": b"A" * 100,
    "beta.txt": b"B" * 250,
    "logs/gamma.log": b"C" * 500,
}
_SENTINEL = b"preexisting"
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
    """With OverwriteMode NEVER, an execution skips all three pre-existing destination objects (0 bytes written,
    their bytes unchanged) and ends ERROR on verification mismatch with the exact ErrorDetail, while ALWAYS
    on the same setup succeeds and replaces them with the source bytes."""
    s3 = ctx.client("s3")

    source = _create_bucket(ctx, "sim2real-ds-src-")
    never_dest = _create_bucket(ctx, "sim2real-ds-never-")
    always_dest = _create_bucket(ctx, "sim2real-ds-always-")
    for key, body in _OBJECTS.items():
        s3.put_object(Bucket=source, Key=key, Body=body)
        s3.put_object(Bucket=never_dest, Key=key, Body=_SENTINEL)
        s3.put_object(Bucket=always_dest, Key=key, Body=_SENTINEL)

    _role_name, role_arn = _create_datasync_role(ctx, [source, never_dest, always_dest])
    source_loc = _create_s3_location(ctx, source, role_arn)
    never_loc = _create_s3_location(ctx, never_dest, role_arn)
    always_loc = _create_s3_location(ctx, always_dest, role_arn)

    never_task = _create_task(ctx, source_loc, never_loc, TransferMode="CHANGED", OverwriteMode="NEVER")
    always_task = _create_task(ctx, source_loc, always_loc, TransferMode="CHANGED", OverwriteMode="ALWAYS")

    # Both executions cost about two minutes of DataSync scheduling; the claim is the contrast
    # between them, so run them together.
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        never_future = pool.submit(_run_execution, ctx, never_task)
        always_future = pool.submit(_run_execution, ctx, always_task)
        _never_arn, never_exec = never_future.result()
        _always_arn, always_exec = always_future.result()

    # The refusal.
    assert never_exec["Status"] == "ERROR", (
        f"OverwriteMode NEVER ended {never_exec['Status']!r}, expected ERROR "
        f"(result {json.dumps(never_exec.get('Result', {}), default=str)})"
    )
    never_result = never_exec["Result"]
    assert never_result["TransferStatus"] == "SUCCESS", (
        f"transfer phase was {never_result['TransferStatus']!r}, expected SUCCESS — the files are skipped, not failed"
    )
    assert never_result["VerifyStatus"] == "ERROR", (
        f"verify phase was {never_result['VerifyStatus']!r}, expected ERROR"
    )
    assert never_result["ErrorCode"] == "CompleteWithErrorNoLogsWithVerificationError", (
        f"error code was {never_result.get('ErrorCode')!r} ({never_result.get('ErrorDetail')!r})"
    )
    expected_detail = (
        "Transfer and verification completed. Verification detected mismatches. To see a list of files "
        "with mismatches in CloudWatch logs, provide a log group when creating or editing a task."
    )
    assert never_result.get("ErrorDetail") == expected_detail, (
        f"error detail was {never_result.get('ErrorDetail')!r}, expected {expected_detail!r}"
    )
    assert never_exec["FilesSkipped"] == len(_OBJECTS), (
        f"FilesSkipped was {never_exec['FilesSkipped']!r}, expected all {len(_OBJECTS)} to be skipped"
    )
    assert never_exec["BytesWritten"] == 0, (
        f"BytesWritten was {never_exec['BytesWritten']!r}; NEVER must write nothing over an existing object"
    )

    # The effect is absent: every destination object is still the pre-existing sentinel.
    never_landed = _bucket_sizes(ctx, never_dest)
    expected_never = {key: len(_SENTINEL) for key in _OBJECTS}
    assert never_landed == expected_never, (
        f"NEVER destination holds {never_landed!r}, expected the untouched {expected_never!r}"
    )
    for key in _OBJECTS:
        got = s3.get_object(Bucket=never_dest, Key=key)["Body"].read()
        assert got == _SENTINEL, (
            f"NEVER destination object {key!r} is {got[:40]!r}, expected the pre-existing {_SENTINEL!r}"
        )

    # Positive control: the same wiring with OverwriteMode ALWAYS does replace them.
    assert always_exec["Status"] == "SUCCESS", (
        f"OverwriteMode ALWAYS ended {always_exec['Status']!r}, expected SUCCESS "
        f"(result {json.dumps(always_exec.get('Result', {}), default=str)})"
    )
    assert always_exec["BytesWritten"] == _TOTAL_BYTES, (
        f"ALWAYS wrote {always_exec['BytesWritten']!r} bytes, expected {_TOTAL_BYTES}"
    )
    always_landed = _bucket_sizes(ctx, always_dest)
    expected_always = {k: len(v) for k, v in _OBJECTS.items()}
    assert always_landed == expected_always, (
        f"ALWAYS destination holds {always_landed!r}, expected {expected_always!r}"
    )
    for key, body in _OBJECTS.items():
        got = s3.get_object(Bucket=always_dest, Key=key)["Body"].read()
        assert got == body, (
            f"ALWAYS destination object {key!r} is {got[:40]!r}, expected the source content"
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
