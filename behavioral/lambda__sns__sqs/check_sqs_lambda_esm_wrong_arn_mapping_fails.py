"""sqs-lambda-esm-wrong-arn-mapping-fails."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

import botocore.exceptions

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sqs-lambda-esm-wrong-arn-mapping-fails"
GROUP = "event-source-mapping"
SERVICES = ["lambda", "sns", "sqs"]


@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """An ESM mapped to one queue's ARN never fires for a different, unmapped queue's traffic."""
    role_arn = _create_lambda_role(ctx)
    sink = _create_queue(ctx, "sink")
    intended = _create_queue(ctx, "intended")
    mapped = _create_queue(ctx, "mapped")
    fn = _create_forwarder_function(ctx, role_arn, sink_queue_url=sink["url"])

    # The ESM is wired to `mapped`, NOT `intended` — simulating a mapping that points at the
    # wrong / stale queue ARN relative to the queue actually receiving new traffic.
    _wire_event_source(ctx, fn["name"], mapped["arn"], batch_size=5)

    sqs = ctx.client("sqs")
    sent = 3
    for i in range(sent):
        sqs.send_message(QueueUrl=intended["url"], MessageBody=f"intended-{i}")

    # Effect absent: messages on the *intended* queue never trigger the function.
    collected: list[dict[str, Any]] = []
    deadline = time.monotonic() + 40.0
    while time.monotonic() < deadline:
        collected.extend(_drain_sink(ctx, sink["url"], wait_s=5))
        if collected:
            break
    assert collected == [], (
        f"function was invoked from the unmapped 'intended' queue: {collected}"
    )
    attrs = sqs.get_queue_attributes(
        QueueUrl=intended["url"], AttributeNames=["ApproximateNumberOfMessages"]
    )["Attributes"]
    assert int(attrs["ApproximateNumberOfMessages"]) >= sent, (
        f"intended queue messages were drained despite no ESM pointing at it: {attrs}"
    )

    # Positive control: the queue actually mapped to the ESM DOES trigger the function.
    for i in range(sent):
        sqs.send_message(QueueUrl=mapped["url"], MessageBody=f"mapped-{i}")

    def probe():
        collected.extend(_drain_sink(ctx, sink["url"], wait_s=3))
        return sum(m["record_count"] for m in collected)

    total = _wait_for_effect(
        probe,
        lambda t: t >= sent,
        timeout_s=90,
        interval_s=3.0,
        description="messages forwarded from the correctly-mapped queue",
    )
    assert total >= sent, (
        f"expected >={sent} forwarded messages from the correctly-mapped queue, got {total}"
    )


_MANAGED_TAG_KEY = "sim2real:managed"


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": _MANAGED_TAG_KEY, "Value": "true"}]


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


_FORWARDER_CODE = """
import json
import os
import boto3

_sqs = boto3.client("sqs")
SINK_QUEUE_URL = os.environ.get("SINK_QUEUE_URL")


def handler(event, context):
    records = event.get("Records", [])
    if records:
        bodies = [r.get("body") for r in records]
        payload = {"kind": "sqs-batch", "record_count": len(records), "bodies": bodies}
    else:
        payload = {"kind": "sns", "event": event}
    if SINK_QUEUE_URL:
        _sqs.send_message(QueueUrl=SINK_QUEUE_URL, MessageBody=json.dumps(payload))
    return {"ok": True}
"""


def _zip_bytes(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", code)
    return buf.getvalue()


def _create_lambda_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-b5-role-")
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
        Tags=_tags_kv(),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn)
    )
    policy_name = ctx.unique_name("sim2real-b5-pol-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": ["sqs:*"], "Resource": "*"}
                ],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    )
    return role_arn


def _create_forwarder_function(ctx, role_arn, sink_queue_url=None, extra_env=None) -> dict:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-b5-fn-")
    env_vars: dict[str, str] = {}
    if sink_queue_url:
        env_vars["SINK_QUEUE_URL"] = sink_queue_url
    if extra_env:
        env_vars.update(extra_env)
    zip_bytes = _zip_bytes(_FORWARDER_CODE)
    resp = None
    last_err = None
    for _ in range(10):
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=30,
                Environment={"Variables": env_vars} if env_vars else {},
                Tags={_MANAGED_TAG_KEY: "true"},
            )
            break
        except botocore.exceptions.ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] == "InvalidParameterValueException":
                time.sleep(3)
                continue
            raise
    if resp is None:
        raise last_err
    arn = resp["FunctionArn"]
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _poll_until(
        lambda: lam.get_function(FunctionName=name)["Configuration"]["State"],
        lambda s: s in ("Active", "Failed"),
        timeout_s=90,
        interval_s=3.0,
        description=f"function {name} Active",
    )
    return {"name": name, "arn": arn}


def _create_queue(ctx, prefix="q") -> dict:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name(f"sim2real-b5-{prefix}-"),
        tags={_MANAGED_TAG_KEY: "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    return {"url": url, "arn": arn}


def _drain_sink(ctx, sink_url, wait_s=2) -> list:
    sqs = ctx.client("sqs")
    out = []
    resp = sqs.receive_message(
        QueueUrl=sink_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait_s
    )
    for m in resp.get("Messages", []):
        out.append(json.loads(m["Body"]))
        sqs.delete_message(QueueUrl=sink_url, ReceiptHandle=m["ReceiptHandle"])
    return out


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
