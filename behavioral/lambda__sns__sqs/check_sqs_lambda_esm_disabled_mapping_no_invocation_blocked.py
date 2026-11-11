"""sqs-lambda-esm-disabled-mapping-no-invocation-blocked."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

import botocore.exceptions

from behavioral_harness import tags

CHECK = "sqs-lambda-esm-disabled-mapping-no-invocation-blocked"
GROUP = "permission-boundary"
SERVICES = ["lambda", "sns", "sqs"]


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """An ESM created with Enabled=False never invokes the function; enabling it does."""
    role_arn = _create_lambda_role(ctx)
    sink = _create_queue(ctx, "sink")
    source = _create_queue(ctx, "src")
    fn = _create_forwarder_function(ctx, role_arn, sink_queue_url=sink["url"])

    lam = ctx.client("lambda")
    esm_uuid = lam.create_event_source_mapping(
        FunctionName=fn["name"],
        EventSourceArn=source["arn"],
        BatchSize=5,
        Enabled=False,
        Tags=dict(_RESOURCE_TAGS),
    )["UUID"]
    ctx.on_cleanup(lambda: lam.delete_event_source_mapping(UUID=esm_uuid))
    _poll_until(
        lambda: lam.get_event_source_mapping(UUID=esm_uuid).get("State"),
        lambda s: s == "Disabled",
        timeout_s=60,
        interval_s=2.0,
        description=f"ESM {esm_uuid} Disabled",
    )

    sqs = ctx.client("sqs")
    sent = 3
    for i in range(sent):
        sqs.send_message(QueueUrl=source["url"], MessageBody=f"disabled-{i}")

    # Effect absent #1: bounded window with no invocation reaching the sink.
    collected: list[dict[str, Any]] = []
    deadline = time.monotonic() + 40.0
    while time.monotonic() < deadline:
        collected.extend(_drain_sink(ctx, sink["url"], wait_s=5))
        if collected:
            break
    assert collected == [], f"disabled ESM invoked the function: {collected}"

    # Effect absent #2: the messages are still sitting on the source queue, unconsumed.
    attrs = sqs.get_queue_attributes(
        QueueUrl=source["url"], AttributeNames=["ApproximateNumberOfMessages"]
    )["Attributes"]
    assert int(attrs["ApproximateNumberOfMessages"]) >= sent, (
        f"messages were drained from the source queue despite a disabled ESM: {attrs}"
    )

    # Positive control: enabling the same mapping lets the very same queued messages through.
    lam.update_event_source_mapping(UUID=esm_uuid, Enabled=True)
    _poll_until(
        lambda: lam.get_event_source_mapping(UUID=esm_uuid).get("State"),
        lambda s: s == "Enabled",
        timeout_s=60,
        interval_s=2.0,
        description=f"ESM {esm_uuid} Enabled",
    )

    def probe():
        collected.extend(_drain_sink(ctx, sink["url"], wait_s=3))
        return sum(m["record_count"] for m in collected)

    total = _wait_for_effect(
        probe,
        lambda t: t >= sent,
        timeout_s=90,
        interval_s=3.0,
        description="messages forwarded after enabling the ESM",
    )
    assert total >= sent, (
        f"enabling the ESM did not forward the queued messages: expected >= {sent}, got {total}"
    )


_RESOURCE_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-b5"}


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
        Tags=[{"Key": k, "Value": v} for k, v in _RESOURCE_TAGS.items()],
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
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=30,
                Environment={"Variables": env_vars} if env_vars else {},
                Tags=dict(_RESOURCE_TAGS),
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
    # An invoked function auto-creates /aws/lambda/<name> on first invocation; it outlives the
    # function, so delete it.
    ctx.on_cleanup(
        lambda: ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}")
    )
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
        tags=dict(_RESOURCE_TAGS),
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
