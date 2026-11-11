"""sqs-lambda-esm-disabled-no-invocation-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

import botocore.exceptions

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sqs-lambda-esm-disabled-no-invocation-negative"
GROUP = "event-source-mapping"
SERVICES = ["lambda", "sns", "sqs"]


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A mapping created with Enabled=False never invokes Lambda and its message stays on the queue,
    while an enabled twin delivers within the same window; enabling the mapping delivers the
    message."""
    role_arn = _create_lambda_role(ctx, "dis")
    src = _create_queue(ctx, "src")
    ctl_src = _create_queue(ctx, "ctl-src")
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
        ctx, handler_source, "dis", role_arn, env={"OUTPUT_QUEUE_URL": out["url"]}
    )

    lam = ctx.client("lambda")
    esm_uuid = lam.create_event_source_mapping(
        FunctionName=fn["name"],
        EventSourceArn=src["arn"],
        BatchSize=10,
        Enabled=False,
    )["UUID"]
    ctx.on_cleanup(lambda: lam.delete_event_source_mapping(UUID=esm_uuid))
    _poll_until(
        lambda: lam.get_event_source_mapping(UUID=esm_uuid).get("State"),
        lambda s: s == "Disabled",
        timeout_s=60,
        interval_s=2.0,
        description=f"ESM {esm_uuid} Disabled",
    )

    ctl_esm_uuid = lam.create_event_source_mapping(
        FunctionName=fn["name"],
        EventSourceArn=ctl_src["arn"],
        BatchSize=10,
        Enabled=True,
    )["UUID"]
    ctx.on_cleanup(lambda: lam.delete_event_source_mapping(UUID=ctl_esm_uuid))
    _poll_until(
        lambda: lam.get_event_source_mapping(UUID=ctl_esm_uuid).get("State"),
        lambda s: s == "Enabled",
        timeout_s=60,
        interval_s=2.0,
        description=f"control ESM {ctl_esm_uuid} Enabled",
    )

    sqs = ctx.client("sqs")
    body = "disabled-esm-message"
    ctl_body = "control-esm-message"
    sqs.send_message(QueueUrl=src["url"], MessageBody=body)
    sqs.send_message(QueueUrl=ctl_src["url"], MessageBody=ctl_body)

    # Bounded wait: the disabled mapping must never pick the message up. The control ESM
    # (identical wiring, Enabled=True) must deliver within this same window, or the window is
    # too short to trust the absence it is supposed to bound.
    deadline = time.monotonic() + 40
    control_delivered: list[str] = []
    while time.monotonic() < deadline:
        for delivered_body in _drain_queue(ctx, out["url"], wait_s=2):
            assert delivered_body != body, (
                "Lambda must not be invoked while the ESM is Disabled"
            )
            control_delivered.append(delivered_body)
        time.sleep(2)
    assert control_delivered, (
        "control ESM (Enabled=True, same wiring) delivered nothing in the window; the disabled "
        "mapping's silence over that same window is not evidence of anything without it"
    )
    assert all(b == ctl_body for b in control_delivered), (
        f"unexpected message body delivered by the control ESM: {control_delivered!r}"
    )

    attrs = sqs.get_queue_attributes(
        QueueUrl=src["url"], AttributeNames=["ApproximateNumberOfMessages"]
    )["Attributes"]
    assert int(attrs["ApproximateNumberOfMessages"]) >= 1, (
        "the message must remain on the source queue while the ESM is disabled"
    )

    # Positive control: re-enabling the same mapping proves the wiring (role, ARNs, env var)
    # was correct and it is specifically the Enabled=False flag that suppressed delivery.
    lam.update_event_source_mapping(UUID=esm_uuid, Enabled=True)
    _poll_until(
        lambda: lam.get_event_source_mapping(UUID=esm_uuid).get("State"),
        lambda s: s == "Enabled",
        timeout_s=90,
        interval_s=3.0,
        description=f"ESM {esm_uuid} Enabled",
    )
    delivered = _wait_for_effect(
        lambda: _drain_queue(ctx, out["url"]),
        lambda msgs: len(msgs) >= 1,
        timeout_s=90,
        interval_s=3.0,
        description="message delivered after re-enabling the ESM",
    )
    assert delivered == [body]


def _resource_tags() -> dict[str, str]:
    return {"sim2real:managed": "true", "sim2real:check": CHECK}


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _resource_tags().items()]


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
        Tags=_tags_kv(),
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
        Tags=_resource_tags(),
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
    params: dict[str, Any] = {"QueueName": q_name}
    if attributes:
        params["Attributes"] = attributes
    params["tags"] = _resource_tags()
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
