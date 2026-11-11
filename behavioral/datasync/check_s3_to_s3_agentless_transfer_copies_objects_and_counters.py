"""s3-to-s3-agentless-transfer-copies-objects-and-counters."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "s3-to-s3-agentless-transfer-copies-objects-and-counters"
GROUP = "data-transfer"
SERVICES = ["datasync"]

_OBJECTS = {
    "alpha.txt": b"A" * 100,
    "beta.txt": b"B" * 250,
    "logs/gamma.log": b"C" * 500,
}
_TOTAL_BYTES = sum(len(b) for b in _OBJECTS.values())


@tags("concern:data-plane", "dp:api", "plane:data", "axis:happy-path", "cap:c1")
def run(ctx) -> None:
    """An agentless S3-to-S3 execution succeeds in every phase, its file and byte counters equal what the source
    holds, and the destination holds the exact source bytes."""
    s3 = ctx.client("s3")
    ds = ctx.client("datasync")

    source = _create_bucket(ctx, "sim2real-ds-src-")
    dest = _create_bucket(ctx, "sim2real-ds-dst-")
    for key, body in _OBJECTS.items():
        s3.put_object(Bucket=source, Key=key, Body=body)

    _role_name, role_arn = _create_datasync_role(ctx, [source, dest])
    source_loc = _create_s3_location(ctx, source, role_arn)
    dest_loc = _create_s3_location(ctx, dest, role_arn)

    task_name = ctx.unique_name("sim2real-ds-task-")
    task = ds.create_task(
        SourceLocationArn=source_loc,
        DestinationLocationArn=dest_loc,
        Name=task_name,
        Options={"VerifyMode": "POINT_IN_TIME_CONSISTENT", "LogLevel": "OFF", "TransferMode": "ALL"},
        Tags=[{"Key": "sim2real", "Value": task_name}],
    )["TaskArn"]
    ctx.on_cleanup(lambda t=task: ds.delete_task(TaskArn=t))

    described = _wait_for_task_available(ctx, task)
    assert described["SourceLocationArn"] == source_loc, (
        f"task source is {described['SourceLocationArn']!r}, expected {source_loc!r}"
    )
    assert described["DestinationLocationArn"] == dest_loc, (
        f"task destination is {described['DestinationLocationArn']!r}, expected {dest_loc!r}"
    )

    execution_arn, execution = _run_execution(ctx, task)
    assert execution["Status"] == "SUCCESS", (
        f"execution ended {execution['Status']!r} (result {json.dumps(execution.get('Result', {}), default=str)})"
    )
    result = execution["Result"]
    assert result["PrepareStatus"] == "SUCCESS", f"prepare phase was {result['PrepareStatus']!r}"
    assert result["TransferStatus"] == "SUCCESS", f"transfer phase was {result['TransferStatus']!r}"
    assert result["VerifyStatus"] == "SUCCESS", f"verify phase was {result['VerifyStatus']!r}"

    assert execution["EstimatedFilesToTransfer"] == len(_OBJECTS), (
        f"EstimatedFilesToTransfer was {execution['EstimatedFilesToTransfer']!r}, expected {len(_OBJECTS)}"
    )
    assert execution["EstimatedBytesToTransfer"] == _TOTAL_BYTES, (
        f"EstimatedBytesToTransfer was {execution['EstimatedBytesToTransfer']!r}, expected {_TOTAL_BYTES}"
    )
    assert execution["FilesTransferred"] == len(_OBJECTS), (
        f"FilesTransferred was {execution['FilesTransferred']!r}, expected {len(_OBJECTS)}"
    )
    assert execution["BytesTransferred"] == _TOTAL_BYTES, (
        f"BytesTransferred was {execution['BytesTransferred']!r}, expected {_TOTAL_BYTES}"
    )
    assert execution["BytesWritten"] == _TOTAL_BYTES, (
        f"BytesWritten was {execution['BytesWritten']!r}, expected {_TOTAL_BYTES}"
    )
    assert execution["FilesVerified"] == len(_OBJECTS), (
        f"FilesVerified was {execution['FilesVerified']!r}, expected {len(_OBJECTS)}"
    )
    assert execution["FilesDeleted"] == 0, (
        f"FilesDeleted was {execution['FilesDeleted']!r}; a pure copy must delete nothing"
    )

    expected_sizes = {k: len(v) for k, v in _OBJECTS.items()}
    landed = _await_bucket_sizes(ctx, dest, expected_sizes)
    assert landed == expected_sizes, (
        f"destination holds {landed!r}, expected {expected_sizes!r}"
    )
    for key, body in _OBJECTS.items():
        got = s3.get_object(Bucket=dest, Key=key)["Body"].read()
        assert got == body, (
            f"destination object {key!r} is {got[:40]!r} ({len(got)} bytes), expected {len(body)} bytes of source content"
        )

    listed = {e["TaskExecutionArn"]: e["Status"] for e in _list_task_executions(ctx, task)}
    assert listed == {execution_arn: "SUCCESS"}, (
        f"ListTaskExecutions for this task returned {listed!r}, expected exactly {execution_arn!r} SUCCESS"
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
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
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


def _wait_for_task_available(ctx, task_arn: str) -> dict:
    ds = ctx.client("datasync")
    deadline = time.monotonic() + 120.0
    described = ds.describe_task(TaskArn=task_arn)
    while time.monotonic() < deadline:
        if described["Status"] != "CREATING":
            break
        time.sleep(3)
        described = ds.describe_task(TaskArn=task_arn)
    assert described["Status"] == "AVAILABLE", (
        f"task settled at {described['Status']!r}, expected AVAILABLE "
        f"(error {described.get('ErrorCode')!r} {described.get('ErrorDetail')!r})"
    )
    return described


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


def _await_bucket_sizes(ctx, bucket: str, expected: dict, timeout_s: float = 60.0) -> dict:
    """Return the destination listing, giving it a bounded chance to settle on ``expected``.

    An execution that reports SUCCESS has finished writing, and one run of this check nonetheless
    observed a listing that did not match while every byte counter did. The wait does not weaken
    the claim — the caller still asserts exact key->size equality and a listing that never settles
    is still a failure — it only keeps a lagging LIST from being read as a lost object.
    """
    deadline = time.monotonic() + timeout_s
    sizes = _bucket_sizes(ctx, bucket)
    while sizes != expected and time.monotonic() < deadline:
        time.sleep(3)
        sizes = _bucket_sizes(ctx, bucket)
    return sizes


def _list_task_executions(ctx, task_arn: str) -> list:
    ds = ctx.client("datasync")
    out = []
    for page in ds.get_paginator("list_task_executions").paginate(TaskArn=task_arn):
        out.extend(page.get("TaskExecutions", []))
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
