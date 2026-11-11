"""sqs-esm-maximum-concurrency-limits-parallel-invocations."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sqs-esm-maximum-concurrency-limits-parallel-invocations"
GROUP = "delivery"
SERVICES = ["lambda", "pipes", "sqs"]

_SLEEP_CODE = """
import json
import os
import time

import boto3

_sqs = boto3.client("sqs")
_RESULTS_URL = os.environ["RESULTS_QUEUE_URL"]
_SLEEP_SECONDS = float(os.environ.get("SLEEP_SECONDS", "5"))


def handler(event, context):
    start = time.time()
    time.sleep(_SLEEP_SECONDS)
    end = time.time()
    records = event.get("Records", [])
    bodies = [r.get("body") for r in records]
    _sqs.send_message(
        QueueUrl=_RESULTS_URL,
        MessageBody=json.dumps({"bodies": bodies, "start": start, "end": end}),
    )
    return {"batchItemFailures": []}
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """ScalingConfig.MaximumConcurrency caps concurrent SQS-driven Lambda invocations: overlapping
    invocation intervals reach but never exceed the cap, and total processing time reflects it."""
    max_concurrency = 2
    sleep_seconds = 5
    n_messages = 8

    source = _create_queue(ctx, "sim2real-esmconc-src-", attributes={"VisibilityTimeout": "90"})
    results = _create_queue(ctx, "sim2real-esmconc-res-")

    role_arn = _create_lambda_role(
        ctx, extra_statements=[{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": results["arn"]}]
    )
    fn_arn = _create_lambda_function(
        ctx,
        ctx.unique_name("sim2real-esmconc-fn-"),
        role_arn,
        _SLEEP_CODE,
        env={"RESULTS_QUEUE_URL": results["url"], "SLEEP_SECONDS": str(sleep_seconds)},
        timeout=30,
    )
    _wire_event_source(
        ctx,
        fn_arn,
        source["arn"],
        batch_size=1,
        extra_config={"ScalingConfig": {"MaximumConcurrency": max_concurrency}},
    )

    sqs = ctx.client("sqs")
    t0 = time.monotonic()
    for i in range(n_messages):
        sqs.send_message(QueueUrl=source["url"], MessageBody=f"esmconc-{i}-{ctx.unique_name('m')}")

    intervals: list[tuple[float, float]] = []
    deadline = time.monotonic() + 180
    while len(intervals) < n_messages and time.monotonic() < deadline:
        for m in _drain_json_messages(ctx, results["url"], wait_s=3):
            intervals.append((m["start"], m["end"]))
        time.sleep(1)
    elapsed = time.monotonic() - t0

    assert len(intervals) == n_messages, f"expected {n_messages} completed invocations, got {len(intervals)}"

    max_overlap = _max_overlap(intervals)
    assert max_overlap <= max_concurrency, (
        f"observed {max_overlap} concurrent invocations, exceeding MaximumConcurrency={max_concurrency}"
    )
    assert max_overlap >= max_concurrency, (
        f"observed only {max_overlap} concurrent invocations with a backlog of {n_messages} messages "
        f"waiting; a mapping that respects MaximumConcurrency={max_concurrency} should still scale up "
        f"to the cap, not merely stay under it"
    )

    # With the cap in force, processing N messages at sleep_seconds each must take at least
    # ceil(N / max_concurrency) rounds; an uncapped mapping (which starts 5 concurrent batches
    # immediately per AWS docs) would finish this workload well under that bound.
    min_expected_elapsed = (n_messages / max_concurrency - 1) * sleep_seconds
    assert elapsed >= min_expected_elapsed, (
        f"processing finished in {elapsed:.1f}s, faster than the MaximumConcurrency={max_concurrency} cap "
        f"should allow for {n_messages} messages at {sleep_seconds}s each (expected >= {min_expected_elapsed:.1f}s)"
    )


def _max_overlap(intervals: list[tuple[float, float]]) -> int:
    events = []
    for start, end in intervals:
        events.append((start, 1))
        events.append((end, -1))
    events.sort(key=lambda e: (e[0], e[1]))
    current = 0
    peak = 0
    for _, delta in events:
        current += delta
        peak = max(peak, current)
    return peak


# ===== helpers =====


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _wire_event_source(ctx, function_name, source_arn, batch_size=10, starting_position=None, extra_config=None) -> str:
    lam = ctx.client("lambda")
    params: dict[str, Any] = {
        "FunctionName": function_name,
        "EventSourceArn": source_arn,
        "BatchSize": batch_size,
        "Enabled": True,
    }
    if starting_position:
        params["StartingPosition"] = starting_position
    elif any(s in source_arn for s in [":stream/", "/stream/", ":kinesis:", ":kafka:", ":documentdb:"]):
        params["StartingPosition"] = "LATEST"
    if extra_config:
        params.update(extra_config)
    params["Tags"] = {"sim2real": CHECK}
    esm_uuid = lam.create_event_source_mapping(**params)["UUID"]
    ctx.on_cleanup(lambda: lam.delete_event_source_mapping(UUID=esm_uuid))
    _poll_until(
        lambda: lam.get_event_source_mapping(UUID=esm_uuid).get("State"),
        lambda s: s == "Enabled",
        timeout_s=90,
        interval_s=3.0,
        description=f"ESM {esm_uuid} Enabled",
    )
    return esm_uuid


def _create_queue(ctx, prefix, fifo=False, attributes=None):
    sqs = ctx.client("sqs")
    name = ctx.unique_name(prefix)
    if fifo:
        name = f"{name}.fifo"
    attrs = dict(attributes or {})
    if fifo:
        attrs["FifoQueue"] = "true"
        attrs.setdefault("ContentBasedDeduplication", "true")
    kwargs: dict[str, Any] = {"QueueName": name, "tags": {"sim2real": CHECK}}
    if attrs:
        kwargs["Attributes"] = attrs
    url = sqs.create_queue(**kwargs)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


def _drain_json_messages(ctx, queue_url, max_messages=10, wait_s=2):
    sqs = ctx.client("sqs")
    out = []
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=max_messages, WaitTimeSeconds=wait_s)
    for m in resp.get("Messages", []):
        try:
            body = json.loads(m["Body"])
        except (json.JSONDecodeError, ValueError):
            body = m["Body"]
        out.append(body)
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    return out


def _make_lambda_zip(code):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_lambda_role(ctx, extra_statements=None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-esmconc-lrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn))
    sqs_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaSQSQueueExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=sqs_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=sqs_policy_arn))
    if extra_statements:
        policy_name = ctx.unique_name("sim2real-esmconc-lpolicy-")
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": extra_statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return resp["Role"]["Arn"]


def _create_lambda_function(ctx, name, role_arn, code, env=None, timeout=30):
    lam = ctx.client("lambda")
    zip_bytes = _make_lambda_zip(code)
    deadline = time.monotonic() + 90
    last_err = None
    resp = None
    ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                Environment={"Variables": env or {}},
                Tags={"sim2real": CHECK},
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            last_err = exc
            time.sleep(2)
    if resp is None:
        raise AssertionError(f"lambda function {name} could not be created: {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return resp["FunctionArn"]


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
