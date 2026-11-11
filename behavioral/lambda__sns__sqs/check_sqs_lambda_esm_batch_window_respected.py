"""sqs-lambda-esm-batch-window-respected."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

import botocore.exceptions

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sqs-lambda-esm-batch-window-respected"
GROUP = "event-source-mapping"
SERVICES = ["lambda", "sns", "sqs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """An event source mapping with MaximumBatchingWindowInSeconds 20 reports that window and
    delivers every queued message exactly once, in at least one invocation of more than one
    record."""
    role_arn = _create_lambda_role(ctx, "win")
    src = _create_queue(ctx, "src")
    out = _create_queue(ctx, "out")

    handler_source = """
import boto3
import json
import os

def handler(event, context):
    sqs = boto3.client("sqs")
    out_url = os.environ["OUTPUT_QUEUE_URL"]
    bodies = [r["body"] for r in event["Records"]]
    sqs.send_message(
        QueueUrl=out_url,
        MessageBody=json.dumps({"count": len(bodies), "bodies": bodies}),
    )
    return {"batchItemFailures": []}
"""
    fn = _create_lambda_function(
        ctx, handler_source, "win", role_arn, env={"OUTPUT_QUEUE_URL": out["url"]}
    )

    # Real AWS runs several concurrent SQS pollers per mapping even at low volume (Lambda
    # keeps ~5 pollers active from the start), so messages trickled in one-at-a-time with
    # gaps get picked up by separate idle pollers instead of accumulating on one of them —
    # the batch window then never gets a chance to combine them. To observe the window's
    # effect deterministically, put the whole backlog on the queue *before* the mapping (and
    # its pollers) exist, so the very first receive call has more than BatchSize-worth of
    # messages to choose from and returns them together in a single batch.
    sqs = ctx.client("sqs")
    sent_bodies = [f"win-msg-{i}" for i in range(12)]
    for i in range(0, len(sent_bodies), 10):
        chunk = sent_bodies[i : i + 10]
        sqs.send_message_batch(
            QueueUrl=src["url"],
            Entries=[{"Id": str(j), "MessageBody": b} for j, b in enumerate(chunk)],
        )

    esm_uuid = _wire_event_source(
        ctx,
        fn["name"],
        src["arn"],
        batch_size=10,
        extra_config={"MaximumBatchingWindowInSeconds": 20},
    )
    mapping = ctx.client("lambda").get_event_source_mapping(UUID=esm_uuid)
    assert mapping.get("MaximumBatchingWindowInSeconds") == 20, (
        f"expected MaximumBatchingWindowInSeconds=20 on the mapping, got {mapping!r}"
    )

    accumulated: list[dict] = []

    def _accumulate_batches() -> list[dict]:
        accumulated.extend(_drain_output_batches(ctx, out["url"]))
        return accumulated

    batches = _wait_for_effect(
        _accumulate_batches,
        lambda batches: sum(b["count"] for b in batches) >= len(sent_bodies),
        timeout_s=90,
        interval_s=3.0,
        description="all messages processed by Lambda",
    )
    total_delivered = sum(b["count"] for b in batches)
    assert total_delivered == len(sent_bodies), (
        f"expected {len(sent_bodies)} total records delivered exactly once, got {total_delivered}"
    )
    delivered_bodies = sorted(b for batch in batches for b in batch["bodies"])
    assert delivered_bodies == sorted(sent_bodies), (
        f"expected delivered bodies to match sent bodies exactly, "
        f"got {delivered_bodies!r} vs {sorted(sent_bodies)!r}"
    )
    max_batch_size = max(b["count"] for b in batches)
    assert max_batch_size > 1, (
        f"MaximumBatchingWindowInSeconds should have combined staggered messages into a "
        f"single batch, but the largest observed batch had only {max_batch_size} record(s): {batches}"
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


def _drain_output_batches(ctx, queue_url: str, wait_s: int = 3) -> list[dict]:
    sqs = ctx.client("sqs")
    batches: list[dict] = []
    resp = sqs.receive_message(
        QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait_s
    )
    for msg in resp.get("Messages", []):
        batches.append(json.loads(msg["Body"]))
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return batches


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
