"""distributed-map-item-reader-input-file-over-10gb-rejected."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "distributed-map-item-reader-input-file-over-10gb-rejected"
GROUP = "distributed_map"
SERVICES = ["stepfunctions", "s3", "iam"]

_HEADERS = ["a", "b", "c", "d"]
_CHUNK_ROW = b"0,0,0,0\n"
_CHUNK_BYTES = 5 * 1024 * 1024  # the multipart minimum part size
_CHUNK_ROWS = _CHUNK_BYTES // len(_CHUNK_ROW)
_CHUNK = _CHUNK_ROW * _CHUNK_ROWS
_GIANT_PARTS = 2200  # 2200 * 5 MiB ~= 10.74 GiB / 11.53 GB, past the 10 GB ItemReader quota either way
_CONTROL_ROWS = [b"1,2,3,4\n", b"5,6,7,8\n", b"9,10,11,12\n"]


def _tags_kv():
    return [{"Key": "sim2real", "Value": CHECK}]


def _sfn_tags():
    return [{"key": "sim2real", "value": CHECK}]


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-dmap-")
    s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _tags_kv()})
    return bucket


def _empty_and_delete_bucket(ctx, bucket):
    s3 = ctx.client("s3")
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _put_giant_object(ctx, bucket, chunk_key, giant_key):
    """Assembles a >10 GB object from ``_GIANT_PARTS`` server-side copies of one 5 MiB chunk."""
    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket, Key=chunk_key, Body=_CHUNK)
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=chunk_key))
    source = f"{bucket}/{chunk_key}"
    upload_id = s3.create_multipart_upload(Bucket=bucket, Key=giant_key)["UploadId"]

    def _abort():
        try:
            s3.abort_multipart_upload(Bucket=bucket, Key=giant_key, UploadId=upload_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchUpload":
                raise

    ctx.on_cleanup(_abort)

    def _copy_part(part_number):
        resp = s3.upload_part_copy(
            Bucket=bucket, Key=giant_key, UploadId=upload_id, PartNumber=part_number,
            CopySource=source, CopySourceRange=f"bytes=0-{_CHUNK_BYTES - 1}",
        )
        return part_number, resp["CopyPartResult"]["ETag"]

    parts = [None] * _GIANT_PARTS
    with ThreadPoolExecutor(max_workers=32) as pool:
        futures = [pool.submit(_copy_part, n) for n in range(1, _GIANT_PARTS + 1)]
        for fut in as_completed(futures):
            part_number, etag = fut.result()
            parts[part_number - 1] = {"PartNumber": part_number, "ETag": etag}
    assert all(parts), "a part copy never reported back"
    s3.complete_multipart_upload(
        Bucket=bucket, Key=giant_key, UploadId=upload_id,
        MultipartUpload={"Parts": parts},
    )
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=giant_key))
    size = s3.head_object(Bucket=bucket, Key=giant_key)["ContentLength"]
    assert size > 10 * 1024 * 1024 * 1024, f"assembled object is only {size} bytes, expected > 10 GiB"


def _create_role(ctx, account_id, bucket):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-dmaprole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
        Description="sim2real-behav sfn distributed-map execution role", Tags=_tags_kv(),
    )["Role"]["Arn"]

    def _delete_role():
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_delete_role)
    statements = [
        {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": f"arn:aws:s3:::{bucket}/*"},
        {
            "Effect": "Allow",
            "Action": ["states:StartExecution", "states:DescribeExecution", "states:StopExecution"],
            "Resource": f"arn:aws:states:{ctx.region}:{account_id}:*",
        },
    ]
    iam.put_role_policy(
        RoleName=role_name, PolicyName="exec",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    return role_arn


def _definition():
    return {
        "StartAt": "Fan",
        "States": {
            "Fan": {
                "Type": "Map",
                "MaxConcurrency": 4,
                "ItemReader": {
                    "Resource": "arn:aws:states:::s3:getObject",
                    "ReaderConfig": {
                        "InputType": "CSV", "CSVHeaderLocation": "GIVEN", "CSVHeaders": _HEADERS,
                    },
                    "Parameters": {"Bucket.$": "$.bucket", "Key.$": "$.key"},
                },
                "ItemProcessor": {
                    "ProcessorConfig": {"Mode": "DISTRIBUTED", "ExecutionType": "EXPRESS"},
                    "StartAt": "P", "States": {"P": {"Type": "Pass", "End": True}},
                },
                "End": True,
            }
        },
    }


def _create_state_machine(ctx, role_arn):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sm-")
    arn = _retry_role_propagation(
        lambda: sfn.create_state_machine(
            name=name, definition=json.dumps(_definition()), roleArn=role_arn,
            type="STANDARD", tags=_sfn_tags(),
        )
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _retry_role_propagation(fn, *, deadline_s: float = 90.0):
    """Retries ``fn`` through IAM trust-policy propagation, which exposes no condition to poll."""
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _run_to_terminal(ctx, sm_arn, input_data, *, timeout_s: float):
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-behav-exec-"),
        input=json.dumps(input_data),
    )["executionArn"]
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, exec_arn))
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(3.0)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {last!r}")


def _best_effort_stop(ctx, exec_arn):
    try:
        ctx.client("stepfunctions").stop_execution(
            executionArn=exec_arn, error="cleanup", cause="sim2real cleanup"
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


def _run_first_execution_through_propagation(ctx, sm_arn, input_data, *, deadline_s: float = 90.0):
    """Retries the first execution through IAM trust-policy propagation of the just-created role,
    which exposes no condition to poll other than the role-assumption failure itself."""
    deadline = time.monotonic() + deadline_s
    while True:
        result = _run_to_terminal(ctx, sm_arn, input_data, timeout_s=120.0)
        propagating = (
            result["status"] == "FAILED"
            and result.get("error") == "States.ItemReaderFailed"
            and "not authorized to assume the provided role" in (result.get("cause") or "")
        )
        if not propagating or time.monotonic() > deadline:
            return result
        time.sleep(3)


def _one_map_run(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    runs = sfn.list_map_runs(executionArn=exec_arn)["mapRuns"]
    assert len(runs) == 1, f"expected exactly one Map Run for {exec_arn}, found {len(runs)}"
    return runs[0]


@tags(
    "axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes",
    "dp:api", "plane:data",
)
def run(ctx) -> None:
    """A Distributed Map whose ItemReader names an S3 object over the 10 GB input-file-size quota
    fails with ItemReaderFailed, while the same machine over a small CSV file succeeds.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/service-quotas.html
    """
    sfn = ctx.client("stepfunctions")
    s3 = ctx.client("s3")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bucket = _create_bucket(ctx)

    control_key = "control.csv"
    s3.put_object(Bucket=bucket, Key=control_key, Body=b"".join(_CONTROL_ROWS))
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=control_key))

    giant_key = "giant.csv"
    _put_giant_object(ctx, bucket, "chunk.csv", giant_key)

    role_arn = _create_role(ctx, account_id, bucket)
    sm_arn = _create_state_machine(ctx, role_arn)

    # ---- positive control: a CSV file well under the quota is read and processed in full ----
    ok = _run_first_execution_through_propagation(ctx, sm_arn, {"bucket": bucket, "key": control_key})
    assert ok["status"] == "SUCCEEDED", (
        f'control over a small CSV file was {ok["status"]!r}: {ok.get("error")!r} {ok.get("cause")!r}'
    )
    ok_counts = sfn.describe_map_run(mapRunArn=_one_map_run(ctx, ok["executionArn"])["mapRunArn"])[
        "itemCounts"
    ]
    assert (ok_counts["total"], ok_counts["succeeded"], ok_counts["failed"]) == (
        len(_CONTROL_ROWS), len(_CONTROL_ROWS), 0,
    ), f"control itemCounts {ok_counts!r}, expected {len(_CONTROL_ROWS)} succeeded and 0 failed"

    # ---- the ONE change: the ItemReader's file is now past the 10 GB input-file-size quota ----
    bad = _run_to_terminal(ctx, sm_arn, {"bucket": bucket, "key": giant_key}, timeout_s=280.0)
    assert bad["status"] == "FAILED", (
        f'over the >10 GB CSV file the run was {bad["status"]!r}, expected FAILED'
    )
    assert bad.get("error") == "States.ItemReaderFailed", (
        f'the oversized-file run failed with {bad.get("error")!r} / {bad.get("cause")!r}, '
        f"expected States.ItemReaderFailed"
    )
    bad_counts = sfn.describe_map_run(mapRunArn=_one_map_run(ctx, bad["executionArn"])["mapRunArn"])[
        "itemCounts"
    ]
    assert (bad_counts["total"], bad_counts["succeeded"], bad_counts["failed"]) == (0, 0, 0), (
        f"the quota-rejected run counted items it could never have read: {bad_counts!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
