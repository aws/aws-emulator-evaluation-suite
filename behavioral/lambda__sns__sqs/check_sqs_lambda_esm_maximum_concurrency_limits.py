"""sqs-lambda-esm-maximum-concurrency-limits."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

import botocore.exceptions

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sqs-lambda-esm-maximum-concurrency-limits"
GROUP = "event-source-mapping"
SERVICES = ["lambda", "sns", "sqs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """ScalingConfig.MaximumConcurrency on an SQS ESM caps how many concurrent Lambda
    invocations may process the backlog at once, even when there is enough backlog to scale
    much higher."""
    role_arn = _create_lambda_role(ctx, "conc")
    src = _create_queue(ctx, "src")
    out = _create_queue(ctx, "out")

    handler_source = """
import boto3
import json
import os
import time

def handler(event, context):
    start = time.time()
    time.sleep(3)
    end = time.time()
    sqs = boto3.client("sqs")
    out_url = os.environ["OUTPUT_QUEUE_URL"]
    sqs.send_message(
        QueueUrl=out_url,
        MessageBody=json.dumps({"start": start, "end": end}),
    )
    return {"batchItemFailures": []}
"""
    fn = _create_lambda_function(
        ctx, handler_source, "conc", role_arn, timeout=15, env={"OUTPUT_QUEUE_URL": out["url"]}
    )

    max_concurrency = 2
    _wire_event_source(
        ctx,
        fn["name"],
        src["arn"],
        batch_size=1,
        extra_config={"ScalingConfig": {"MaximumConcurrency": max_concurrency}},
    )

    sqs = ctx.client("sqs")
    num_messages = 16
    entries = [
        {"Id": str(i), "MessageBody": f"conc-msg-{i}"} for i in range(10)
    ]
    sqs.send_message_batch(QueueUrl=src["url"], Entries=entries)
    entries2 = [
        {"Id": str(i), "MessageBody": f"conc-msg-{i}"}
        for i in range(10, num_messages)
    ]
    sqs.send_message_batch(QueueUrl=src["url"], Entries=entries2)

    accumulated: list[dict] = []

    def _accumulate() -> list[dict]:
        accumulated.extend(_drain_json(ctx, out["url"]))
        return accumulated

    intervals = _wait_for_effect(
        _accumulate,
        lambda evs: len(evs) >= num_messages,
        timeout_s=240,
        interval_s=4.0,
        description=f"all {num_messages} backlog messages processed",
    )
    assert len(intervals) == num_messages, (
        f"expected all {num_messages} backlog messages to be drained to the output queue, "
        f"got {len(intervals)}"
    )

    observed_max = _max_overlap([(e["start"], e["end"]) for e in intervals])
    assert observed_max <= max_concurrency, (
        f"observed {observed_max} concurrent invocations, but MaximumConcurrency={max_concurrency} "
        f"should have capped it"
    )
    assert observed_max >= 2, (
        f"expected the ESM to actually scale up to the configured concurrency (>=2) while "
        f"draining a backlog of {num_messages} messages, but max observed overlap was {observed_max}"
    )


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
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
    """Poll for an async cross-service effect (default 120s — Kinesis/DDB-stream ESMs can need
    60-120s for cold-start + first delivery; fast effects return as soon as the predicate holds)."""
    return _poll_until(
        probe,
        predicate,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=description,
    )


def _wire_event_source(
    ctx,
    function_name,
    source_arn,
    batch_size=10,
    starting_position=None,
    extra_config=None,
) -> str:
    """Create an event-source mapping (SQS/DynamoDB Streams/Kinesis/...) and wait until Enabled
    (registers delete_event_source_mapping teardown). Returns the ESM UUID."""
    lam = ctx.client("lambda")
    params: dict[str, Any] = {
        "FunctionName": function_name,
        "EventSourceArn": source_arn,
        "BatchSize": batch_size,
        "Enabled": True,
    }
    if starting_position:
        params["StartingPosition"] = starting_position
    elif any(
        s in source_arn
        for s in [":stream/", "/stream/", ":kinesis:", ":kafka:", ":documentdb:"]
    ):
        params["StartingPosition"] = "LATEST"
    if extra_config:
        params.update(extra_config)
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


def _lambda_zip(handler_source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_source)
    return buf.getvalue()


def _create_lambda_role(ctx, name_suffix: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"sim2real-role-{name_suffix}-")
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    sqs_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaSQSQueueExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_arn)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_arn)
    )
    iam.attach_role_policy(RoleName=role_name, PolicyArn=sqs_arn)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=sqs_arn)
    )
    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": "*"}
        ],
    }
    policy_name = f"{role_name}-inline"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(inline_policy),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    )
    return role_arn


def _create_lambda_function(
    ctx, handler_source: str, name_suffix: str, role_arn: str, timeout=30, env=None
) -> dict[str, str]:
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name(f"sim2real-fn-{name_suffix}-")
    zip_bytes = _lambda_zip(handler_source)
    params: dict[str, Any] = dict(
        FunctionName=fn_name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": zip_bytes},
        Timeout=timeout,
        MemorySize=128,
        Publish=True,
    )
    if env:
        params["Environment"] = {"Variables": env}
    params["Tags"] = {"sim2real": CHECK}
    deadline = time.monotonic() + 60
    resp = None
    last_err = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(**params)
            break
        except botocore.exceptions.ClientError as err:
            if err.response["Error"]["Code"] == "InvalidParameterValueException":
                last_err = err
                time.sleep(3)
                continue
            raise
    if resp is None:
        raise last_err
    fn_arn = resp["FunctionArn"]
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=fn_name).get("State"),
        lambda s: s == "Active",
        timeout_s=60,
        interval_s=2.0,
        description=f"function {fn_name} Active",
    )
    return {"name": fn_name, "arn": fn_arn}


def _create_queue(ctx, name_suffix: str, attributes=None) -> dict[str, str]:
    sqs = ctx.client("sqs")
    q_name = ctx.unique_name(f"sim2real-q-{name_suffix}-")
    params: dict[str, Any] = {"QueueName": q_name, "tags": {"sim2real": CHECK}}
    if attributes:
        params["Attributes"] = attributes
    url = sqs.create_queue(**params)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    return {"url": url, "arn": arn}


def _drain_json(ctx, queue_url: str, wait_s: int = 4) -> list[dict]:
    sqs = ctx.client("sqs")
    out: list[dict] = []
    resp = sqs.receive_message(
        QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait_s
    )
    for msg in resp.get("Messages", []):
        out.append(json.loads(msg["Body"]))
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return out


def _max_overlap(intervals: list[tuple[float, float]]) -> int:
    """Sweep-line: the maximum number of intervals active at any single instant."""
    events: list[tuple[float, int]] = []
    for start, end in intervals:
        events.append((start, 1))
        events.append((end, -1))
    events.sort()
    current = 0
    best = 0
    for _, delta in events:
        current += delta
        best = max(best, current)
    return best


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
