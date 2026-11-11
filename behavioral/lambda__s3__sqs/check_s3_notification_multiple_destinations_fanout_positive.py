"""s3-notification-multiple-destinations-fanout-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

import botocore

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "s3-notification-multiple-destinations-fanout-positive"
GROUP = "event-propagation"
SERVICES = ["lambda", "s3", "sqs"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A single bucket configured with prefix-scoped notification rules fans out
    matching uploads to the correct destination: an "sqs/" prefix routes to SQS and
    a "lambda/" prefix routes to Lambda, independently."""
    s3 = ctx.client("s3")
    bucket_name = _create_bucket(ctx)
    queue_url, queue_arn = _create_queue(ctx)
    _set_queue_policy_for_s3(ctx, queue_url, queue_arn, bucket_name)
    role_arn = _create_lambda_role(ctx)
    fn_name, fn_arn = _create_lambda_function(ctx, role_arn, _LOG_HANDLER_CODE)
    _add_s3_invoke_permission(ctx, fn_name, bucket_name)

    s3.put_bucket_notification_configuration(
        Bucket=bucket_name,
        NotificationConfiguration={
            "QueueConfigurations": [
                {
                    "QueueArn": queue_arn,
                    "Events": ["s3:ObjectCreated:*"],
                    "Filter": {
                        "Key": {"FilterRules": [{"Name": "prefix", "Value": "sqs/"}]}
                    },
                }
            ],
            "LambdaFunctionConfigurations": [
                {
                    "LambdaFunctionArn": fn_arn,
                    "Events": ["s3:ObjectCreated:*"],
                    "Filter": {
                        "Key": {
                            "FilterRules": [{"Name": "prefix", "Value": "lambda/"}]
                        }
                    },
                }
            ],
        },
    )

    sqs_key = "sqs/routed-to-queue.txt"
    lambda_key = "lambda/routed-to-function.txt"
    since_ms = int(time.time() * 1000) - 5000
    s3.put_object(Bucket=bucket_name, Key=sqs_key, Body=b"queue-bound")
    s3.put_object(Bucket=bucket_name, Key=lambda_key, Body=b"lambda-bound")

    # sqs/-prefixed upload lands in the queue. The collection holds open past the
    # positive control's own latency so a mis-routed lambda/ event arriving late is
    # still caught, instead of the poll returning the instant any message shows up.
    sqs_records = _poll_for_sqs_records(ctx, queue_url, sqs_key, timeout_s=90.0)
    sqs_matches = [r for r in sqs_records if r["s3"]["object"]["key"] == sqs_key]
    assert sqs_matches, f"sqs-prefixed key not delivered to queue: {sqs_records}"
    assert not any(r["s3"]["object"]["key"] == lambda_key for r in sqs_records), (
        "lambda-prefixed key unexpectedly delivered to queue"
    )

    # lambda/-prefixed upload invokes the function; same calibrated hold on this leg.
    lambda_messages = _poll_for_marker(
        ctx, fn_name, since_ms, "S3_EVT::", lambda_key, timeout_s=90.0
    )
    lambda_records = [_parse_record(m) for m in lambda_messages]
    lambda_matches = [r for r in lambda_records if r and r["s3"]["object"]["key"] == lambda_key]
    assert lambda_matches, f"lambda-prefixed key not observed by function: {lambda_records}"
    assert not any(
        r and r["s3"]["object"]["key"] == sqs_key for r in lambda_records
    ), "sqs-prefixed key unexpectedly invoked the function"


_MANAGED_TAG_KEY = "sim2real:managed"


def _resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true"}


def _resource_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _resource_tags().items()]


_LOG_HANDLER_CODE = """
import json

def handler(event, context):
    for record in event.get("Records", []):
        print("S3_EVT::" + json.dumps(record))
    return {"received": len(event.get("Records", []))}
"""


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _wait_for_effect(
    probe, predicate, timeout_s=120.0, interval_s=2.0, description="effect"
):
    return _poll_until(
        probe,
        predicate,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=description,
    )


def _lambda_zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_lambda_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-s3fan-role-")
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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=_resource_tags_kv(),
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
    fn_name = ctx.unique_name("sim2real-s3fan-fn-")
    kwargs: dict[str, Any] = dict(
        FunctionName=fn_name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": _lambda_zip(code)},
        Timeout=timeout,
        Tags=_resource_tags(),
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
                time.sleep(3)
                continue
            raise
    if fn_arn is None:
        raise AssertionError(f"could not create lambda function: {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=fn_name).get("State"),
        lambda s: s == "Active",
        timeout_s=60,
        interval_s=2.0,
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
    bucket_name = ctx.unique_name("sim2real-s3fan-bkt-")
    kwargs: dict[str, Any] = {"Bucket": bucket_name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": _resource_tags_kv()})

    def _cleanup():
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


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    queue_name = ctx.unique_name("sim2real-s3fan-q-")
    queue_url = sqs.create_queue(QueueName=queue_name, tags=_resource_tags())["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]
    return queue_url, queue_arn


def _set_queue_policy_for_s3(ctx, queue_url: str, queue_arn: str, bucket_name: str):
    sqs = ctx.client("sqs")
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowS3Notify",
                "Effect": "Allow",
                "Principal": {"Service": "s3.amazonaws.com"},
                "Action": "SQS:SendMessage",
                "Resource": queue_arn,
                "Condition": {
                    "ArnEquals": {"aws:SourceArn": f"arn:aws:s3:::{bucket_name}"}
                },
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})


def _poll_for_sqs_records(
    ctx,
    queue_url: str,
    target_key: str,
    timeout_s: float = 90.0,
    extra_window_s: float = 10.0,
) -> list[dict[str, Any]]:
    """Collect S3 event records delivered to the queue. Waits for target_key specifically
    (the positive control), then holds the queue open for max(extra_window_s, 3x that
    latency) so a mis-routed event arriving after the control is still captured instead of
    the poll returning the instant any single message shows up."""
    sqs = ctx.client("sqs")
    collected: list[dict[str, Any]] = []
    start = time.monotonic()

    def probe():
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        )
        for msg in resp.get("Messages", []):
            body = json.loads(msg["Body"])
            for rec in body.get("Records", []):
                collected.append(rec)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        return collected

    _wait_for_effect(
        probe,
        lambda recs: any(r["s3"]["object"]["key"] == target_key for r in recs),
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"S3 event for {target_key!r} delivered to queue {queue_url}",
    )
    latency_s = time.monotonic() - start
    hold_deadline = time.monotonic() + max(extra_window_s, 3 * latency_s)
    while time.monotonic() < hold_deadline:
        probe()
        time.sleep(5.0)
    return collected


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
    ctx,
    function_name: str,
    since_ms: int,
    marker: str,
    target_key: str,
    timeout_s: float = 90.0,
    extra_window_s: float = 10.0,
) -> list[str]:
    """Collect Records-bearing log lines. Waits for target_key specifically (the positive
    control), then holds open for max(extra_window_s, 3x that latency) so an invocation
    carrying a mis-routed key that lands after the control is still captured."""
    start = time.monotonic()

    def probe():
        events = _fetch_log_events(ctx, function_name, since_ms)
        return [e["message"] for e in events if marker in e["message"]]

    def _has_target(msgs: list[str]) -> bool:
        for m in msgs:
            rec = _parse_record(m)
            if rec and rec["s3"]["object"]["key"] == target_key:
                return True
        return False

    _wait_for_effect(
        probe,
        _has_target,
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"log message for {target_key!r} containing {marker!r} for {function_name}",
    )
    latency_s = time.monotonic() - start
    hold_deadline = time.monotonic() + max(extra_window_s, 3 * latency_s)
    last: list[str] = []
    while time.monotonic() < hold_deadline:
        last = probe()
        time.sleep(5.0)
    return last


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
