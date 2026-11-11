"""s3-notification-multipart-upload-complete-triggers-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

import botocore

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "s3-notification-multipart-upload-complete-triggers-positive"
GROUP = "event-propagation"
SERVICES = ["lambda", "s3", "sqs"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """Completing a multipart upload fires the ObjectCreated:CompleteMultipartUpload
    notification and invokes the target Lambda exactly once for that object."""
    s3 = ctx.client("s3")
    bucket_name = _create_bucket(ctx)
    role_arn = _create_lambda_role(ctx)
    fn_name, fn_arn = _create_lambda_function(ctx, role_arn, _LOG_HANDLER_CODE)
    _add_s3_invoke_permission(ctx, fn_name, bucket_name)

    s3.put_bucket_notification_configuration(
        Bucket=bucket_name,
        NotificationConfiguration={
            "LambdaFunctionConfigurations": [
                {"LambdaFunctionArn": fn_arn, "Events": ["s3:ObjectCreated:*"]}
            ]
        },
    )

    key = "uploads/multipart-object.bin"
    since_ms = int(time.time() * 1000) - 5000
    upload_id = s3.create_multipart_upload(Bucket=bucket_name, Key=key)["UploadId"]
    part = s3.upload_part(
        Bucket=bucket_name,
        Key=key,
        PartNumber=1,
        UploadId=upload_id,
        Body=b"single-part-multipart-payload",
    )
    s3.complete_multipart_upload(
        Bucket=bucket_name,
        Key=key,
        UploadId=upload_id,
        MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": part["ETag"]}]},
    )

    messages = _poll_for_marker(ctx, fn_name, since_ms, "S3_EVT::", timeout_s=_budget_s(ctx, 90.0))
    records = [_parse_record(m) for m in messages]
    matches = [r for r in records if r and r["s3"]["object"]["key"] == key]
    assert matches, f"no lambda-observed record for key {key} in {records}"
    assert matches[0]["eventName"] == "ObjectCreated:CompleteMultipartUpload", (
        f"expected eventName ObjectCreated:CompleteMultipartUpload, got {matches[0]['eventName']!r}"
    )

    # Actively poll a settle window to confirm no duplicate invocation for this
    # object arrives after the first one (rather than asserting immediately).
    settle_deadline = time.monotonic() + 10.0
    final_matches: list[dict[str, Any]] = []
    while time.monotonic() < settle_deadline:
        all_messages = _fetch_log_events(ctx, fn_name, since_ms)
        final_matches = [
            r
            for r in (_parse_record(e["message"]) for e in all_messages)
            if r and r["s3"]["object"]["key"] == key
        ]
        if len(final_matches) > 1:
            break
        time.sleep(1.0)
    assert len(final_matches) == 1, f"expected exactly 1 invocation, got {final_matches}"


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


_LOG_HANDLER_CODE = """
import json

def handler(event, context):
    for record in event.get("Records", []):
        print("S3_EVT::" + json.dumps(record))
    return {"received": len(event.get("Records", []))}
"""


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition", ctx=None
):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _wait_for_effect(
    probe, predicate, timeout_s=120.0, interval_s=2.0, description="effect", ctx=None
):
    return _poll_until(
        probe,
        predicate,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=description,
        ctx=ctx,
    )


def _lambda_zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_lambda_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-s3lam-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_policy_arn = (
        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    )
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn)
    )
    return role_arn


def _create_lambda_function(ctx, role_arn: str, code: str, env=None, timeout=30):
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-s3lam-fn-")
    kwargs: dict[str, Any] = dict(
        FunctionName=fn_name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": _lambda_zip(code)},
        Timeout=timeout,
    )
    if env:
        kwargs["Environment"] = {"Variables": env}
    deadline = time.monotonic() + 60
    fn_arn = None
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(**kwargs)
            fn_arn = resp["FunctionArn"]
            break
        except botocore.exceptions.ClientError as err:
            if err.response["Error"]["Code"] == "InvalidParameterValueException":
                last_err = err
                time.sleep(2)
                continue
            raise
    if fn_arn is None:
        raise AssertionError(f"could not create lambda function: {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=fn_name).get("State"),
        lambda s: s == "Active",
        timeout_s=60,
        interval_s=1.0,
        description=f"lambda function {fn_name} Active",
    )
    return fn_name, fn_arn


def _add_s3_invoke_permission(ctx, function_name: str, bucket_name: str) -> None:
    lam = ctx.client("lambda")
    lam.add_permission(
        FunctionName=function_name,
        StatementId="AllowS3Invoke",
        Action="lambda:InvokeFunction",
        Principal="s3.amazonaws.com",
        SourceArn=f"arn:aws:s3:::{bucket_name}",
    )


def _create_bucket(ctx, versioned: bool = False) -> str:
    s3 = ctx.client("s3")
    bucket_name = ctx.unique_name("sim2real-s3lam-bkt-")
    kwargs: dict[str, Any] = {"Bucket": bucket_name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _cleanup():
        # abort any leftover multipart uploads before deleting objects/bucket
        for upload in s3.list_multipart_uploads(Bucket=bucket_name).get("Uploads", []):
            s3.abort_multipart_upload(
                Bucket=bucket_name, Key=upload["Key"], UploadId=upload["UploadId"]
            )
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket_name):
            objs = [
                {"Key": v["Key"], "VersionId": v["VersionId"]}
                for v in page.get("Versions", [])
            ]
            objs += [
                {"Key": v["Key"], "VersionId": v["VersionId"]}
                for v in page.get("DeleteMarkers", [])
            ]
            if objs:
                failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket_name)

    ctx.on_cleanup(_cleanup)
    if versioned:
        s3.put_bucket_versioning(
            Bucket=bucket_name, VersioningConfiguration={"Status": "Enabled"}
        )
    return bucket_name


def _fetch_log_events(ctx, function_name: str, since_ms: int) -> list[dict[str, Any]]:
    logs = ctx.client("logs")
    log_group = f"/aws/lambda/{function_name}"
    try:
        resp = logs.filter_log_events(logGroupName=log_group, startTime=since_ms)
    except botocore.exceptions.ClientError as err:
        if err.response["Error"]["Code"] == "ResourceNotFoundException":
            return []
        raise
    return resp.get("events", [])


def _poll_for_marker(
    ctx, function_name: str, since_ms: int, marker: str, timeout_s: float = 90.0
) -> list[str]:
    def probe():
        events = _fetch_log_events(ctx, function_name, since_ms)
        return [e["message"] for e in events if marker in e["message"]]

    return _wait_for_effect(
        probe,
        lambda msgs: len(msgs) > 0,
        timeout_s=timeout_s,
        interval_s=1.0,
        description=f"log message containing {marker!r} for {function_name}",
        ctx=ctx,
    )


def _parse_record(message: str) -> dict[str, Any] | None:
    idx = message.find("S3_EVT::")
    if idx == -1:
        return None
    try:
        return json.loads(message[idx + len("S3_EVT::") :].strip())
    except json.JSONDecodeError:
        return None


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
