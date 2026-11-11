"""sqs-esm-fifo-queue-message-group-ordering-preserved."""
from __future__ import annotations

import io
import json
import time
import uuid
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sqs-esm-fifo-queue-message-group-ordering-preserved"
GROUP = "data-format"
SERVICES = ["lambda", "pipes", "sqs"]

_FORWARD_CODE = """
import json
import os
import uuid

import boto3

_sqs = boto3.client("sqs")
_RESULTS_URL = os.environ["RESULTS_QUEUE_URL"]


def handler(event, context):
    records = event.get("Records", [])
    bodies = [r.get("body") for r in records]
    _sqs.send_message(
        QueueUrl=_RESULTS_URL,
        MessageBody=json.dumps({"bodies": bodies}),
        MessageGroupId="results",
        MessageDeduplicationId=str(uuid.uuid4()),
    )
    return {"batchItemFailures": []}
"""


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """An event source mapping on a FIFO queue with one message group delivers every record, and the
    sequence reconstructed across batches equals the send order exactly."""
    source = _create_queue(ctx, "sim2real-esmfifo-src-", fifo=True)
    # Results queue is FIFO too, single group, so the harness receives forwarded batches in the
    # exact order the (single-concurrency, single message-group) Lambda invocations produced them.
    results = _create_queue(ctx, "sim2real-esmfifo-res-", fifo=True)

    role_arn = _create_lambda_role(
        ctx, extra_statements=[{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": results["arn"]}]
    )
    fn_arn = _create_lambda_function(
        ctx, ctx.unique_name("sim2real-esmfifo-fn-"), role_arn, _FORWARD_CODE, env={"RESULTS_QUEUE_URL": results["url"]}
    )
    _wire_event_source(ctx, fn_arn, source["arn"], batch_size=10)

    sqs = ctx.client("sqs")
    group_id = "group-a"
    n = 12
    bodies = [f"seq-{i:03d}-{ctx.unique_name('t')}" for i in range(n)]
    for i, body in enumerate(bodies):
        sqs.send_message(
            QueueUrl=source["url"],
            MessageBody=body,
            MessageGroupId=group_id,
            MessageDeduplicationId=f"{group_id}-{i}-{uuid.uuid4()}",
        )

    def _collect_forwarded():
        collected: list[str] = []
        deadline = time.monotonic() + 90
        while len(collected) < n and time.monotonic() < deadline:
            resp = sqs.receive_message(
                QueueUrl=results["url"], MaxNumberOfMessages=10, WaitTimeSeconds=3
            )
            for m in resp.get("Messages", []):
                payload = json.loads(m["Body"])
                collected.extend(payload["bodies"])
                sqs.delete_message(QueueUrl=results["url"], ReceiptHandle=m["ReceiptHandle"])
        return collected

    reconstructed = _collect_forwarded()
    assert len(reconstructed) == n, f"expected {n} forwarded bodies, got {len(reconstructed)}: {reconstructed}"
    assert reconstructed == bodies, (
        "FIFO message-group order was not preserved end-to-end through the event source mapping: "
        f"expected {bodies}, got {reconstructed}"
    )


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


def _make_lambda_zip(code):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_lambda_role(ctx, extra_statements=None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-esmfifo-lrole-")
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
        policy_name = ctx.unique_name("sim2real-esmfifo-lpolicy-")
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
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
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
            time.sleep(5)
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
