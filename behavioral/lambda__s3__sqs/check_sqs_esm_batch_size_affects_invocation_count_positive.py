"""sqs-esm-batch-size-affects-invocation-count-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sqs-esm-batch-size-affects-invocation-count-positive"
GROUP = "event-source-mapping"
SERVICES = ["lambda", "s3", "sqs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """With BatchSize=1 every invocation gets at most one record; raising BatchSize (plus a batching
    window) via UpdateEventSourceMapping lifts that bound on the next burst.
    """
    bucket = _create_bucket(ctx)
    role_arn = _create_role(ctx)
    queue = _create_queue(ctx)
    fn = _create_function(ctx, role_arn, {"REPORT_BUCKET": bucket, "REPORT_PREFIX": "reports/"})
    esm_uuid = _create_esm(ctx, fn["name"], queue["arn"], batch_size=1)

    sqs = ctx.client("sqs")
    run_id = ctx.unique_name("batch1-")
    markers = {f"{run_id}-{i}" for i in range(5)}
    for marker in markers:
        sqs.send_message(QueueUrl=queue["url"], MessageBody=marker)

    def _all_seen(reports: list[dict[str, Any]]) -> bool:
        seen = {rec["body"] for rep in reports for rec in rep["records"]}
        return markers.issubset(seen)

    reports = _poll_reports(ctx, bucket, "reports/", _all_seen, timeout_s=150)
    seen = {rec["body"] for rep in reports for rec in rep["records"]}
    assert markers.issubset(seen), f"not all messages were delivered: missing {markers - seen}"
    for rep in reports:
        our_records = [rec for rec in rep["records"] if rec["body"] in markers]
        if our_records:
            assert rep["record_count"] <= 1, (
                f"BatchSize=1 violated: a single invocation delivered {rep['record_count']} records"
            )

    lam = ctx.client("lambda")
    lam.update_event_source_mapping(UUID=esm_uuid, BatchSize=10, MaximumBatchingWindowInSeconds=10)
    _wait_for_esm_batch_size(ctx, esm_uuid, 10, batching_window=10)

    run_id2 = ctx.unique_name("batch10-")
    markers2 = [f"{run_id2}-{i}" for i in range(8)]
    sqs.send_message_batch(
        QueueUrl=queue["url"],
        Entries=[{"Id": str(i), "MessageBody": marker} for i, marker in enumerate(markers2)],
    )

    def _all_seen2(reports: list[dict[str, Any]]) -> bool:
        seen2 = {rec["body"] for rep in reports for rec in rep["records"]}
        return set(markers2).issubset(seen2)

    reports2 = _poll_reports(ctx, bucket, "reports/", _all_seen2, timeout_s=150)
    seen2 = {rec["body"] for rep in reports2 for rec in rep["records"]}
    assert set(markers2).issubset(seen2), f"not all post-update messages were delivered: missing {set(markers2) - seen2}"
    post_update_reports = [rep for rep in reports2 if any(rec["body"] in markers2 for rec in rep["records"])]
    max_batch = max(rep["record_count"] for rep in post_update_reports)
    assert max_batch > 1, (
        f"raising BatchSize to 10 never produced an invocation with more than one record "
        f"(max observed={max_batch}); batch size is not affecting invocation count"
    )



_ROLE_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)

_MANAGED_POLICIES = [
    "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    "arn:aws:iam::aws:policy/AmazonS3FullAccess",
    "arn:aws:iam::aws:policy/AmazonSQSFullAccess",
]

_LAMBDA_CODE = '''
import json
import os
import time
import uuid

import boto3

s3 = boto3.client("s3")
BUCKET = os.environ["REPORT_BUCKET"]
PREFIX = os.environ.get("REPORT_PREFIX", "reports/")
FAIL_MARKER = os.environ.get("FAIL_MARKER", "")
FAIL_UNTIL_RECEIVE_COUNT = int(os.environ.get("FAIL_UNTIL_RECEIVE_COUNT", "0"))
SLEEP_SECONDS = float(os.environ.get("SLEEP_SECONDS", "0"))


def handler(event, context):
    records = event.get("Records", [])
    report = {"request_id": context.aws_request_id, "record_count": len(records), "records": []}
    should_fail = False
    for r in records:
        body = r.get("body", "")
        receive_count = int(r.get("attributes", {}).get("ApproximateReceiveCount", "1"))
        report["records"].append({
            "message_id": r.get("messageId"),
            "body": body,
            "message_attributes": r.get("messageAttributes", {}),
            "receive_count": receive_count,
        })
        if FAIL_MARKER and FAIL_MARKER in body:
            if FAIL_UNTIL_RECEIVE_COUNT == 0 or receive_count < FAIL_UNTIL_RECEIVE_COUNT:
                should_fail = True
    if SLEEP_SECONDS:
        time.sleep(SLEEP_SECONDS)
    key = PREFIX + report["request_id"] + "-" + uuid.uuid4().hex[:8] + ".json"
    s3.put_object(Bucket=BUCKET, Key=key, Body=json.dumps(report).encode("utf-8"))
    if should_fail:
        raise RuntimeError("intentional-failure-for-test")
    return {"batchItemFailures": []}
'''


def _build_zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", code)
    return buf.getvalue()


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-xsvc-bkt-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, name: str) -> None:
    s3 = ctx.client("s3")
    try:
        resp = s3.list_objects_v2(Bucket=name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    s3.delete_bucket(Bucket=name)


def _create_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-xsvc-role-")
    role_arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=_ROLE_TRUST_POLICY)["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, name))
    for policy_arn in _MANAGED_POLICIES:
        iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
    return role_arn


def _delete_role(ctx, name: str) -> None:
    iam = ctx.client("iam")
    for policy_arn in _MANAGED_POLICIES:
        try:
            iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
    iam.delete_role(RoleName=name)


def _create_function(ctx, role_arn: str, env: dict[str, str], timeout: int = 30) -> dict[str, str]:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-xsvc-fn-")
    code_zip = _build_zip(_LAMBDA_CODE)
    last_err = None
    resp = None
    ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
    # A new execution role is not assumable by Lambda at once: retry its InvalidParameterValue to a deadline.
    left = ctx.time_left()
    deadline = time.monotonic() + (100.0 if left is None else min(100.0, left))
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": code_zip},
                Timeout=timeout,
                Environment={"Variables": env},
            )
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            time.sleep(2)
    if resp is None:
        raise AssertionError(f"create_function never succeeded (role propagation?): {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return {"name": name, "arn": resp["FunctionArn"]}


def _create_queue(ctx, attributes: dict[str, str] | None = None) -> dict[str, str]:
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-xsvc-q-")
    kwargs: dict[str, Any] = {"QueueName": name}
    if attributes:
        kwargs["Attributes"] = attributes
    url = sqs.create_queue(**kwargs)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


def _create_esm(
    ctx,
    function_name: str,
    queue_arn: str,
    batch_size: int = 1,
    enabled: bool = True,
    batching_window: int | None = None,
    filter_criteria: dict[str, Any] | None = None,
) -> str:
    lam = ctx.client("lambda")
    kwargs: dict[str, Any] = {
        "EventSourceArn": queue_arn,
        "FunctionName": function_name,
        "BatchSize": batch_size,
        "Enabled": enabled,
    }
    if batching_window is not None:
        kwargs["MaximumBatchingWindowInSeconds"] = batching_window
    if filter_criteria is not None:
        kwargs["FilterCriteria"] = filter_criteria
    esm_uuid = lam.create_event_source_mapping(**kwargs)["UUID"]
    ctx.on_cleanup(lambda: _delete_esm(ctx, esm_uuid))
    _wait_for_esm_state(ctx, esm_uuid, "Enabled" if enabled else "Disabled")
    return esm_uuid


def _delete_esm(ctx, esm_uuid: str) -> None:
    lam = ctx.client("lambda")
    try:
        lam.delete_event_source_mapping(UUID=esm_uuid)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_for_esm_state(ctx, esm_uuid: str, desired_state: str, timeout_s: float = 120.0) -> str:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = lam.get_event_source_mapping(UUID=esm_uuid)["State"]
        if state == desired_state:
            return state
        time.sleep(3)
    raise AssertionError(f"event source mapping never reached {desired_state!r}, last state={state!r}")


def _wait_for_esm_batch_size(
    ctx, esm_uuid: str, batch_size: int, batching_window: int | None = None, timeout_s: float = 120.0
) -> None:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_event_source_mapping(UUID=esm_uuid)
        if (
            last.get("State") == "Enabled"
            and last.get("BatchSize") == batch_size
            and (batching_window is None or last.get("MaximumBatchingWindowInSeconds") == batching_window)
        ):
            return
        time.sleep(3)
    raise AssertionError(
        f"ESM {esm_uuid} never reached BatchSize={batch_size} "
        f"batching_window={batching_window} while Enabled, last={last}"
    )


def _poll_reports(
    ctx, bucket: str, prefix: str, predicate, timeout_s: float = 120.0, interval_s: float = 3.0
) -> list[dict[str, Any]]:
    s3 = ctx.client("s3")
    deadline = time.monotonic() + timeout_s
    reports: list[dict[str, Any]] = []
    while time.monotonic() < deadline:
        resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
        keys = [o["Key"] for o in resp.get("Contents", [])]
        reports = []
        for key in keys:
            body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
            reports.append(json.loads(body))
        if predicate(reports):
            return reports
        time.sleep(interval_s)
    return reports


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line, if it exists."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
