"""sqs-lambda-esm-wrong-queue-arn-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

import botocore.exceptions

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sqs-lambda-esm-wrong-queue-arn-negative"
GROUP = "event-source-mapping"
SERVICES = ["lambda", "sns", "sqs"]


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """An ESM wired to one queue's ARN never triggers Lambda for messages sent to a
    different (mismatched) queue, even though that queue genuinely exists; messages sent to
    the correctly-wired queue (positive control, same file) still trigger delivery."""
    role_arn = _create_lambda_role(ctx, "warn")
    configured_queue = _create_queue(ctx, "configured")
    decoy_queue = _create_queue(ctx, "decoy")
    out = _create_queue(ctx, "out")

    handler_source = """
import boto3
import os

def handler(event, context):
    sqs = boto3.client("sqs")
    out_url = os.environ["OUTPUT_QUEUE_URL"]
    for record in event["Records"]:
        sqs.send_message(QueueUrl=out_url, MessageBody=record["body"])
    return {"batchItemFailures": []}
"""
    fn = _create_lambda_function(
        ctx, handler_source, "warn", role_arn, env={"OUTPUT_QUEUE_URL": out["url"]}
    )
    # The ESM is wired to `configured_queue`'s ARN — simulating a config drift where the
    # ESM was pointed at the wrong (but real, existing) queue.
    _wire_event_source(ctx, fn["name"], configured_queue["arn"], batch_size=10)

    sqs = ctx.client("sqs")
    decoy_body = "sent-to-mismatched-decoy-queue"
    sqs.send_message(QueueUrl=decoy_queue["url"], MessageBody=decoy_body)

    # Bounded wait: messages sent to the decoy queue must never reach Lambda.
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        assert _drain_queue(ctx, out["url"], wait_s=2) == [], (
            "Lambda must not be invoked for a queue the ESM is not wired to"
        )
        time.sleep(2)

    decoy_attrs = sqs.get_queue_attributes(
        QueueUrl=decoy_queue["url"], AttributeNames=["ApproximateNumberOfMessages"]
    )["Attributes"]
    assert int(decoy_attrs["ApproximateNumberOfMessages"]) >= 1, (
        "the message on the unwired decoy queue must remain unconsumed"
    )

    # Positive control: the same ESM does deliver messages sent to the queue it is actually
    # wired to, proving the negative result above is about the ARN mismatch, not broken wiring.
    configured_body = "sent-to-correctly-wired-queue"
    sqs.send_message(QueueUrl=configured_queue["url"], MessageBody=configured_body)
    delivered = _wait_for_effect(
        lambda: _drain_queue(ctx, out["url"]),
        lambda msgs: len(msgs) >= 1,
        timeout_s=90,
        interval_s=3.0,
        description="message delivered from the correctly-wired queue",
    )
    assert delivered == [configured_body], (
        f"expected [{configured_body!r}] delivered from the correctly-wired queue, got {delivered!r}"
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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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
        Tags={"sim2real:managed": "true"},
    )
    if env:
        params["Environment"] = {"Variables": env}
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
    params: dict[str, Any] = {"QueueName": q_name, "tags": {"sim2real:managed": "true"}}
    if attributes:
        params["Attributes"] = attributes
    url = sqs.create_queue(**params)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    return {"url": url, "arn": arn}


def _drain_queue(ctx, queue_url: str, wait_s: int = 2) -> list[str]:
    sqs = ctx.client("sqs")
    bodies: list[str] = []
    resp = sqs.receive_message(
        QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait_s
    )
    for msg in resp.get("Messages", []):
        bodies.append(msg["Body"])
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return bodies


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
