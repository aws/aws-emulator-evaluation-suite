"""sqs-esm-wrong-queue-arn-no-invocation-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sqs-esm-wrong-queue-arn-no-invocation-negative"
GROUP = "overly-permissive"
SERVICES = ["lambda", "pipes", "sqs"]

_FORWARD_CODE = """
import json
import os
import time

import boto3

_sqs = boto3.client("sqs")
_RESULTS_URL = os.environ["RESULTS_QUEUE_URL"]


def handler(event, context):
    records = event.get("Records", [])
    bodies = [r.get("body") for r in records]
    _sqs.send_message(
        QueueUrl=_RESULTS_URL,
        MessageBody=json.dumps({"bodies": bodies, "count": len(records), "ts": time.time()}),
    )
    return {"batchItemFailures": []}
"""


@tags("axis:negative-delivery", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """A message sent to a queue the mapping does not watch never reaches the Lambda and stays on that
    queue, while a message sent to the watched queue is delivered."""
    watched = _create_queue(ctx, "sim2real-esmwrong-watched-")
    mismatched = _create_queue(ctx, "sim2real-esmwrong-decoy-")
    results = _create_queue(ctx, "sim2real-esmwrong-res-")

    role_arn = _create_lambda_role(
        ctx, extra_statements=[{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": results["arn"]}]
    )
    fn_arn = _create_lambda_function(
        ctx, ctx.unique_name("sim2real-esmwrong-fn-"), role_arn, _FORWARD_CODE, env={"RESULTS_QUEUE_URL": results["url"]}
    )
    # The mapping is wired only to `watched`; `mismatched` is never connected to any mapping.
    _wire_event_source(ctx, fn_arn, watched["arn"], batch_size=1)

    sqs = ctx.client("sqs")

    # break exactly one thing: send to the queue the mapping does NOT watch
    mismatched_body = f"esmwrong-blocked-{ctx.unique_name('m')}"
    sqs.send_message(QueueUrl=mismatched["url"], MessageBody=mismatched_body)

    observe_deadline = time.monotonic() + 45
    seen_bodies: set[str] = set()
    while time.monotonic() < observe_deadline:
        for m in _drain_json_messages(ctx, results["url"], wait_s=3):
            seen_bodies.update(m.get("bodies", []))
        if mismatched_body in seen_bodies:
            break
        time.sleep(2)
    assert mismatched_body not in seen_bodies, "a message on the unmapped queue must never reach the target Lambda"

    # effect must be absent: the message is still enqueued on the mismatched queue, unconsumed
    direct = sqs.receive_message(
        QueueUrl=mismatched["url"], MaxNumberOfMessages=1, WaitTimeSeconds=5, VisibilityTimeout=5
    )
    direct_bodies = {m["Body"] for m in direct.get("Messages", [])}
    assert mismatched_body in direct_bodies, "message on the unmapped queue must remain there, unconsumed"

    # positive control: same mapping, message sent to the queue it actually watches
    watched_body = f"esmwrong-ok-{ctx.unique_name('m')}"
    sqs.send_message(QueueUrl=watched["url"], MessageBody=watched_body)
    delivered = _wait_for_effect(
        lambda: _drain_json_messages(ctx, results["url"]),
        lambda msgs: any(watched_body in m.get("bodies", []) for m in msgs),
        timeout_s=60,
        description="delivery from the correctly-mapped queue",
    )
    assert any(watched_body in m.get("bodies", []) for m in delivered), (
        f"expected {watched_body!r} forwarded from the watched queue's mapping, got {delivered!r}"
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


def _wait_for_effect(probe, predicate, timeout_s=120.0, interval_s=2.0, description="effect"):
    return _poll_until(probe, predicate, timeout_s=timeout_s, interval_s=interval_s, description=description)


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
    kwargs: dict[str, Any] = {"QueueName": name, "tags": {"sim2real:managed": "true"}}
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
    role_name = ctx.unique_name("sim2real-esmwrong-lrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn))
    sqs_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaSQSQueueExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=sqs_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=sqs_policy_arn))
    if extra_statements:
        policy_name = ctx.unique_name("sim2real-esmwrong-lpolicy-")
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
                Tags={"sim2real:managed": "true"},
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
