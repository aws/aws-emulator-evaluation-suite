"""sqs-lambda-esm-filter-criteria-suppresses-non-matching."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

import botocore.exceptions

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sqs-lambda-esm-filter-criteria-suppresses-non-matching"
GROUP = "event-source-mapping"
SERVICES = ["lambda", "sns", "sqs"]


@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """ESM FilterCriteria non-matching messages never reach the Lambda invocation payload."""
    role_arn = _create_lambda_role(ctx)
    sink = _create_queue(ctx, "sink")
    source = _create_queue(ctx, "src")
    fn = _create_forwarder_function(ctx, role_arn, sink_queue_url=sink["url"])
    filter_criteria = {
        "Filters": [{"Pattern": json.dumps({"body": {"type": ["order"]}})}]
    }
    _wire_event_source(
        ctx,
        fn["name"],
        source["arn"],
        batch_size=5,
        extra_config={"FilterCriteria": filter_criteria},
    )

    sqs = ctx.client("sqs")
    non_matching_bodies = [
        json.dumps({"type": "shipment", "id": f"shipment-{i}"}) for i in range(3)
    ]
    for body in non_matching_bodies:
        sqs.send_message(QueueUrl=source["url"], MessageBody=body)

    collected: list[dict[str, Any]] = []

    def leaked_non_matching() -> list[str]:
        return [
            b
            for m in collected
            for b in m.get("bodies", [])
            if b in non_matching_bodies
        ]

    # Bounded absence window: confirm none of the non-matching messages are forwarded within it.
    # This window alone is not the full proof — a target whose first delivery is merely slower than
    # 40s (an SQS ESM's first delivery can take tens of seconds) would
    # score a false absence here, so the leak check is re-asserted below across the entire run.
    deadline = time.monotonic() + 40.0
    while time.monotonic() < deadline:
        collected.extend(_drain_sink(ctx, sink["url"], wait_s=5))
        if leaked_non_matching():
            break
    assert leaked_non_matching() == [], (
        f"non-matching messages were delivered to lambda: {leaked_non_matching()}"
    )

    # Positive control: the ESM (and its filter) is alive — a matching message DOES get through.
    matching_body = json.dumps({"type": "order", "id": "order-99"})
    sqs.send_message(QueueUrl=source["url"], MessageBody=matching_body)

    def probe():
        collected.extend(_drain_sink(ctx, sink["url"], wait_s=3))
        return [m for m in collected if matching_body in m.get("bodies", [])]

    matches = _wait_for_effect(
        probe,
        lambda ms: len(ms) >= 1,
        timeout_s=90,
        interval_s=3.0,
        description="positive-control matching message forwarded to lambda",
    )
    assert len(matches) == 1
    assert matches[0]["bodies"] == [matching_body]

    # Re-assert absence over the FULL run, not just the initial window: a non-matching message
    # that leaked in only after the 40s cutoff (while polling for the positive control) must still
    # be caught.
    assert leaked_non_matching() == [], (
        f"non-matching messages leaked to lambda during the run: {leaked_non_matching()}"
    )

    # Consumption: real Lambda deletes a filtered-out record from the source queue without ever
    # invoking the function. An emulator that "filters" by simply never reading the message leaves
    # it stuck here — the single most commonly wrong emulator behaviour on this axis.
    _wait_for_effect(
        lambda: _queue_message_count(ctx, source["url"]),
        lambda n: n == 0,
        timeout_s=60,
        interval_s=3.0,
        description="source queue drained (non-matching records consumed, not stuck)",
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
        Tags=[{"Key": "sim2real:check", "Value": CHECK}],
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
                Tags={"sim2real:check": CHECK},
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
        tags={"sim2real:check": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    return {"url": url, "arn": arn}


def _queue_message_count(ctx, queue_url) -> int:
    sqs = ctx.client("sqs")
    attrs = sqs.get_queue_attributes(
        QueueUrl=queue_url,
        AttributeNames=[
            "ApproximateNumberOfMessages",
            "ApproximateNumberOfMessagesNotVisible",
        ],
    )["Attributes"]
    return int(attrs["ApproximateNumberOfMessages"]) + int(
        attrs["ApproximateNumberOfMessagesNotVisible"]
    )


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
