"""simple-pattern-filters-partition-the-transferred-set."""
from __future__ import annotations

import concurrent.futures
import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "simple-pattern-filters-partition-the-transferred-set"
GROUP = "data-transfer"
SERVICES = ["datasync"]

_OBJECTS = {
    "alpha.txt": b"A" * 100,
    "beta.txt": b"B" * 250,
    "logs/gamma.log": b"C" * 500,
}
_PATTERN = "/logs*"
_MATCHING = {"logs/gamma.log"}
_COMPLEMENT = {"alpha.txt", "beta.txt"}


@tags("concern:data-plane", "dp:api", "plane:data", "axis:happy-path", "cap:c1")
def run(ctx) -> None:
    """Executions with the same pattern as Excludes and as Includes land disjoint halves whose union is the
    source, each with its exact bytes, and each execution's file and byte counters describe only its half."""
    s3 = ctx.client("s3")
    ds = ctx.client("datasync")

    source = _create_bucket(ctx, "sim2real-ds-src-")
    excl_dest = _create_bucket(ctx, "sim2real-ds-excl-")
    incl_dest = _create_bucket(ctx, "sim2real-ds-incl-")
    for key, body in _OBJECTS.items():
        s3.put_object(Bucket=source, Key=key, Body=body)

    _role_name, role_arn = _create_datasync_role(ctx, [source, excl_dest, incl_dest])
    source_loc = _create_s3_location(ctx, source, role_arn)
    excl_loc = _create_s3_location(ctx, excl_dest, role_arn)
    incl_loc = _create_s3_location(ctx, incl_dest, role_arn)

    rule = [{"FilterType": "SIMPLE_PATTERN", "Value": _PATTERN}]
    excl_task = _create_task(ctx, source_loc, excl_loc, Excludes=rule)
    incl_task = _create_task(ctx, source_loc, incl_loc, Includes=rule)

    # Run both halves concurrently: each execution costs about two minutes of DataSync
    # scheduling, and the partition claim is about the pair.
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        excl_future = pool.submit(_run_execution, ctx, excl_task)
        incl_future = pool.submit(_run_execution, ctx, incl_task)
        _excl_arn, excl_exec = excl_future.result()
        _incl_arn, incl_exec = incl_future.result()

    assert excl_exec["Status"] == "SUCCESS", (
        f"excluding {_PATTERN!r} ended {excl_exec['Status']!r} "
        f"(result {json.dumps(excl_exec.get('Result', {}), default=str)})"
    )
    assert incl_exec["Status"] == "SUCCESS", (
        f"including {_PATTERN!r} ended {incl_exec['Status']!r} "
        f"(result {json.dumps(incl_exec.get('Result', {}), default=str)})"
    )
    assert excl_exec["Excludes"] == rule, (
        f"execution reported Excludes {excl_exec['Excludes']!r}, expected {rule!r}"
    )
    assert incl_exec["Includes"] == rule, (
        f"execution reported Includes {incl_exec['Includes']!r}, expected {rule!r}"
    )

    excl_landed = _bucket_sizes(ctx, excl_dest)
    incl_landed = _bucket_sizes(ctx, incl_dest)
    assert set(excl_landed) == _COMPLEMENT, (
        f"excluding {_PATTERN!r} landed {sorted(excl_landed)!r}, expected {sorted(_COMPLEMENT)!r}"
    )
    assert set(incl_landed) == _MATCHING, (
        f"including {_PATTERN!r} landed {sorted(incl_landed)!r}, expected {sorted(_MATCHING)!r}"
    )
    assert set(excl_landed) & set(incl_landed) == set(), (
        f"the two halves overlap on {sorted(set(excl_landed) & set(incl_landed))!r}"
    )
    assert set(excl_landed) | set(incl_landed) == set(_OBJECTS), (
        f"the two halves cover {sorted(set(excl_landed) | set(incl_landed))!r}, not the source {sorted(_OBJECTS)!r}"
    )

    excl_bytes = sum(len(_OBJECTS[k]) for k in _COMPLEMENT)
    incl_bytes = sum(len(_OBJECTS[k]) for k in _MATCHING)
    assert excl_exec["FilesTransferred"] == len(_COMPLEMENT), (
        f"excluding {_PATTERN!r} transferred {excl_exec['FilesTransferred']!r} files, expected {len(_COMPLEMENT)}"
    )
    assert excl_exec["BytesTransferred"] == excl_bytes, (
        f"excluding {_PATTERN!r} transferred {excl_exec['BytesTransferred']!r} bytes, expected {excl_bytes}"
    )
    assert incl_exec["FilesTransferred"] == len(_MATCHING), (
        f"including {_PATTERN!r} transferred {incl_exec['FilesTransferred']!r} files, expected {len(_MATCHING)}"
    )
    assert incl_exec["BytesTransferred"] == incl_bytes, (
        f"including {_PATTERN!r} transferred {incl_exec['BytesTransferred']!r} bytes, expected {incl_bytes}"
    )

    for key in _COMPLEMENT:
        got = s3.get_object(Bucket=excl_dest, Key=key)["Body"].read()
        assert got == _OBJECTS[key], (
            f"excluded-half object {key!r} is {len(got)} bytes, expected {len(_OBJECTS[key])}"
        )
    for key in _MATCHING:
        got = s3.get_object(Bucket=incl_dest, Key=key)["Body"].read()
        assert got == _OBJECTS[key], (
            f"included-half object {key!r} is {len(got)} bytes, expected {len(_OBJECTS[key])}"
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


def _create_task(ctx, source_loc: str, dest_loc: str, **kwargs) -> str:
    ds = ctx.client("datasync")
    name = ctx.unique_name("sim2real-ds-task-")
    task = ds.create_task(
        SourceLocationArn=source_loc,
        DestinationLocationArn=dest_loc,
        Name=name,
        Options={"VerifyMode": "POINT_IN_TIME_CONSISTENT", "LogLevel": "OFF", "TransferMode": "ALL"},
        Tags=[{"Key": "sim2real", "Value": name}],
        **kwargs,
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
