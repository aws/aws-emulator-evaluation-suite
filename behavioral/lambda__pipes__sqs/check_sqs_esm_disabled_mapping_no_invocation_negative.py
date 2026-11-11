"""sqs-esm-disabled-mapping-no-invocation-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sqs-esm-disabled-mapping-no-invocation-negative"
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


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """A message sent while the SQS event source mapping is Disabled never reaches the function and
    stays on the queue, and the same mapping, re-enabled, delivers that message; a warm-up message
    sent while it is enabled is delivered first."""
    # The queue's VisibilityTimeout must be >= the Lambda's function timeout (AWS requires this
    # for SQS event source mappings, and recommends VisibilityTimeout be several times the
    # function timeout to allow for retries). Pin the function timeout well below the queue's
    # visibility window so the pairing is valid on real AWS.
    function_timeout = 10
    visibility_timeout = 30
    assert visibility_timeout >= function_timeout, "queue VisibilityTimeout must be >= the Lambda function timeout"

    source = _create_queue(ctx, "sim2real-esmdis-src-", attributes={"VisibilityTimeout": str(visibility_timeout)})
    results = _create_queue(ctx, "sim2real-esmdis-res-")

    role_arn = _create_lambda_role(
        ctx, extra_statements=[{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": results["arn"]}]
    )
    fn_arn = _create_lambda_function(
        ctx,
        ctx.unique_name("sim2real-esmdis-fn-"),
        role_arn,
        _FORWARD_CODE,
        env={"RESULTS_QUEUE_URL": results["url"]},
        timeout=function_timeout,
    )
    esm_uuid = _wire_event_source(ctx, fn_arn, source["arn"], batch_size=1)

    lam = ctx.client("lambda")
    sqs = ctx.client("sqs")

    # Confirm the RESULTING state, not just the parameters we sent: the queue's actual configured
    # VisibilityTimeout and the function's actual configured Timeout must satisfy the AWS
    # requirement (VisibilityTimeout >= function timeout) for this SQS event source mapping.
    fn_config = lam.get_function_configuration(FunctionName=fn_arn)
    actual_fn_timeout = fn_config["Timeout"]
    actual_visibility_timeout = int(
        sqs.get_queue_attributes(QueueUrl=source["url"], AttributeNames=["VisibilityTimeout"])["Attributes"][
            "VisibilityTimeout"
        ]
    )
    assert actual_fn_timeout == function_timeout
    assert actual_visibility_timeout == visibility_timeout
    assert actual_visibility_timeout >= actual_fn_timeout, (
        f"queue VisibilityTimeout ({actual_visibility_timeout}s) must be >= the function's configured "
        f"Timeout ({actual_fn_timeout}s) for a valid SQS event source mapping"
    )

    # sanity: mapping works while enabled
    warm_body = f"esmdis-warm-{ctx.unique_name('m')}"
    warmup_start = time.monotonic()
    sqs.send_message(QueueUrl=source["url"], MessageBody=warm_body)
    _wait_for_effect(
        lambda: _drain_json_messages(ctx, results["url"]),
        lambda msgs: any(warm_body in m.get("bodies", []) for m in msgs),
        timeout_s=60,
        description="warm-up delivery while enabled",
    )
    warmup_latency_s = time.monotonic() - warmup_start

    # break exactly one thing: disable the mapping
    lam.update_event_source_mapping(UUID=esm_uuid, Enabled=False)
    _poll_until(
        lambda: lam.get_event_source_mapping(UUID=esm_uuid).get("State"),
        lambda s: s == "Disabled",
        timeout_s=60,
        interval_s=2,
        description=f"ESM {esm_uuid} Disabled",
    )

    # State reads "Disabled" before Lambda's pollers stop: in-flight long-poll receives drain over
    # about one polling cycle and can still deliver a message sent meanwhile. AWS exposes no signal
    # for the drain, so this is a fixed wait, not a predicate poll.
    drain_deadline = time.monotonic() + 45
    while time.monotonic() < drain_deadline:
        time.sleep(1)

    disabled_body = f"esmdis-blocked-{ctx.unique_name('m')}"
    sqs.send_message(QueueUrl=source["url"], MessageBody=disabled_body)

    # Observe for at least 3x the warm-up delivery's latency (and at least 60 s), sampling the
    # results queue throughout.
    observe_deadline = time.monotonic() + max(60.0, 3 * warmup_latency_s)
    seen_bodies: set[str] = set()
    while time.monotonic() < observe_deadline:
        for m in _drain_json_messages(ctx, results["url"], wait_s=3):
            seen_bodies.update(m.get("bodies", []))
        if disabled_body in seen_bodies:
            break
        time.sleep(2)
    assert disabled_body not in seen_bodies, "disabled mapping must never invoke the target Lambda"


    # effect must be absent: the message is still enqueued, never consumed
    direct = sqs.receive_message(QueueUrl=source["url"], MaxNumberOfMessages=1, WaitTimeSeconds=5, VisibilityTimeout=5)
    direct_bodies = {m["Body"] for m in direct.get("Messages", [])}
    assert disabled_body in direct_bodies, "message must remain on the queue while the mapping is disabled"

    # positive control (same mapping, re-enabled): delivery resumes for the very same message
    lam.update_event_source_mapping(UUID=esm_uuid, Enabled=True)
    _poll_until(
        lambda: lam.get_event_source_mapping(UUID=esm_uuid).get("State"),
        lambda s: s == "Enabled",
        timeout_s=60,
        interval_s=2,
        description=f"ESM {esm_uuid} re-Enabled",
    )
    delivered = _wait_for_effect(
        lambda: _drain_json_messages(ctx, results["url"]),
        lambda msgs: any(disabled_body in m.get("bodies", []) for m in msgs),
        timeout_s=60,
        description="delivery resumes once re-enabled",
    )
    assert any(disabled_body in m.get("bodies", []) for m in delivered)


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
    kwargs: dict[str, Any] = {"QueueName": name, "tags": {"sim2real-check": CHECK}}
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
    role_name = ctx.unique_name("sim2real-esmdis-lrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn))
    sqs_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaSQSQueueExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=sqs_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=sqs_policy_arn))
    if extra_statements:
        policy_name = ctx.unique_name("sim2real-esmdis-lpolicy-")
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
                Tags={"sim2real-check": CHECK},
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
