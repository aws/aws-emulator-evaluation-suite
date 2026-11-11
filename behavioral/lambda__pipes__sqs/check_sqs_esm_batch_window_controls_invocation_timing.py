"""sqs-esm-batch-window-controls-invocation-timing."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sqs-esm-batch-window-controls-invocation-timing"
GROUP = "delivery"
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


# timing:real-time — buffer: 20 s https://docs.aws.amazon.com/lambda/latest/dg/invocation-eventsourcemapping.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx: Any) -> None:
    """MaximumBatchingWindowInSeconds delays invocation until the window elapses when the batch
    isn't filled: a mapping with a 20s window takes measurably longer to invoke on a single,
    sub-batch-size message than an otherwise identical mapping with the default (0s) window."""
    # --- control: no batching window configured -> invokes promptly on the lone message ---
    ctrl_source = _create_queue(ctx, "sim2real-esmbw-csrc-")
    ctrl_results = _create_queue(ctx, "sim2real-esmbw-cres-")

    # --- variant: 20s batching window configured, batch size never fills with a single message ---
    window_seconds = 20
    var_source = _create_queue(ctx, "sim2real-esmbw-vsrc-")
    var_results = _create_queue(ctx, "sim2real-esmbw-vres-")

    # The shared role must be able to forward to BOTH result queues (created above) — grant
    # sqs:SendMessage on their ARNs explicitly; the managed AWSLambdaSQSQueueExecutionRole policy
    # only covers receiving/deleting from the *source* side, not sending to an arbitrary queue.
    role_arn = _create_lambda_role(
        ctx,
        extra_statements=[
            {
                "Effect": "Allow",
                "Action": "sqs:SendMessage",
                "Resource": [ctrl_results["arn"], var_results["arn"]],
            }
        ],
    )

    ctrl_fn_arn = _create_lambda_function(
        ctx,
        ctx.unique_name("sim2real-esmbw-cfn-"),
        role_arn,
        _FORWARD_CODE,
        env={"RESULTS_QUEUE_URL": ctrl_results["url"]},
    )
    _wire_event_source(ctx, ctrl_fn_arn, ctrl_source["arn"], batch_size=10)

    sqs = ctx.client("sqs")
    ctrl_body = f"esmbw-ctrl-{ctx.unique_name('m')}"
    ctrl_t0 = time.monotonic()
    sqs.send_message(QueueUrl=ctrl_source["url"], MessageBody=ctrl_body)
    _wait_for_effect(
        lambda: _drain_json_messages(ctx, ctrl_results["url"]),
        lambda msgs: any(ctrl_body in m.get("bodies", []) for m in msgs),
        timeout_s=120,
        description="control (window=0) delivery",
    )
    control_delay = time.monotonic() - ctrl_t0

    var_fn_arn = _create_lambda_function(
        ctx,
        ctx.unique_name("sim2real-esmbw-vfn-"),
        role_arn,
        _FORWARD_CODE,
        env={"RESULTS_QUEUE_URL": var_results["url"]},
    )
    _wire_event_source(
        ctx,
        var_fn_arn,
        var_source["arn"],
        batch_size=10,
        extra_config={"MaximumBatchingWindowInSeconds": window_seconds},
    )

    var_body = f"esmbw-var-{ctx.unique_name('m')}"
    var_t0 = time.monotonic()
    sqs.send_message(QueueUrl=var_source["url"], MessageBody=var_body)
    _wait_for_effect(
        lambda: _drain_json_messages(ctx, var_results["url"]),
        lambda msgs: any(var_body in m.get("bodies", []) for m in msgs),
        timeout_s=180,
        description="variant (window=20s) delivery",
    )
    variant_delay = time.monotonic() - var_t0

    # Both paths share the same poller-startup / cold-start overhead; only the batching window
    # differs, so allow generous absolute bounds but require the *relative* delay to reflect it.
    # elapsed-bound: a mapping with no batching window invokes before a 20 s window would elapse.
    assert control_delay < window_seconds + 30, (
        f"control invocation took {control_delay:.1f}s, expected it to be faster than the "
        f"{window_seconds}s batching window used in the variant (plus startup slack)"
    )
    assert variant_delay >= window_seconds * 0.5, (
        f"variant invocation delay {variant_delay:.1f}s too fast to be consistent with a "
        f"{window_seconds}s batching window"
    )
    assert variant_delay - control_delay >= window_seconds * 0.4, (
        f"batching window did not measurably delay invocation relative to the control: "
        f"control={control_delay:.1f}s variant={variant_delay:.1f}s"
    )


# ===== helpers =====

_MANAGED_TAG_KEY = "sim2real:managed"


def _esmbw_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": "sim2real-esmbw"}


def _esmbw_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _esmbw_resource_tags().items()]


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
    kwargs: dict[str, Any] = {"QueueName": name, "tags": _esmbw_resource_tags()}
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
    role_name = ctx.unique_name("sim2real-esmbw-lrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    resp = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_esmbw_tags_kv()
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn))
    sqs_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaSQSQueueExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=sqs_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=sqs_policy_arn))
    if extra_statements:
        policy_name = ctx.unique_name("sim2real-esmbw-lpolicy-")
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
    ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                Environment={"Variables": env or {}},
                Tags=_esmbw_resource_tags(),
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            last_err = exc
            time.sleep(2)
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
