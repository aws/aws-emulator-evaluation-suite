"""sqs-esm-maximum-batching-window-respected."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sqs-esm-maximum-batching-window-respected"
GROUP = "esm-advanced"
SERVICES = ["lambda", "stepfunctions", "sqs"]

_HANDLER_CODE = """
import boto3, json, os, time
sqs = boto3.client("sqs")
RESULTS_QUEUE = os.environ["RESULTS_QUEUE_URL"]

def handler(event, context):
    received_at = time.time()
    for r in event.get("Records", []):
        sqs.send_message(
            QueueUrl=RESULTS_QUEUE,
            MessageBody=json.dumps({"body": r["body"], "receivedAt": received_at}),
        )
    return {"batchItemFailures": []}
"""

BATCHING_WINDOW_S = 10


# timing:real-time — buffer: 10 s https://docs.aws.amazon.com/lambda/latest/dg/with-sqs.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """MaximumBatchingWindowInSeconds delays invocation until the window elapses."""
    sqs = ctx.client("sqs")
    source = _create_queue(ctx)
    results = _create_queue(ctx)
    role_arn = _create_lambda_role(ctx)
    fn_name = _create_function(ctx, role_arn, _HANDLER_CODE, env={"RESULTS_QUEUE_URL": results["url"]})
    # BatchSize is far larger than the single message we send, so the only thing
    # that can trigger the invocation is the batching window elapsing.
    _create_esm(ctx, source["arn"], fn_name, BatchSize=10, MaximumBatchingWindowInSeconds=BATCHING_WINDOW_S)

    send_time = time.monotonic()
    sqs.send_message(QueueUrl=source["url"], MessageBody="batching-window-probe")

    payload = None
    deadline = time.monotonic() + 90.0
    while payload is None and time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=results["url"], MaxNumberOfMessages=1, WaitTimeSeconds=5)
        for m in resp.get("Messages", []):
            payload = json.loads(m["Body"])
            sqs.delete_message(QueueUrl=results["url"], ReceiptHandle=m["ReceiptHandle"])

    assert payload is not None, "lambda was never invoked for the batching-window message"
    delay_s = time.monotonic() - send_time
    assert delay_s >= BATCHING_WINDOW_S - 2, (
        f"invocation happened after only {delay_s:.1f}s, before the "
        f"{BATCHING_WINDOW_S}s batching window could have elapsed"
    )
    assert delay_s <= 60, f"invocation delayed {delay_s:.1f}s, far beyond the configured window"


# ===== helpers =====


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float = 2.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _make_zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_queue(ctx, *, fifo: bool = False, attrs: dict | None = None) -> dict[str, str]:
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-esmq-")
    attributes = dict(attrs or {})
    if fifo:
        name += ".fifo"
        attributes["FifoQueue"] = "true"
    url = sqs.create_queue(
        QueueName=name,
        Attributes=attributes,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-esmq"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


def _create_lambda_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-esmrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    policy_arns = [
        "arn:aws:iam::aws:policy/service-role/AWSLambdaSQSQueueExecutionRole",
        "arn:aws:iam::aws:policy/AmazonSQSFullAccess",
    ]
    for arn in policy_arns:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)

    def _cleanup() -> None:
        for arn in policy_arns:
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_function(ctx, role_arn: str, code: str, *, timeout: int = 30, env: dict | None = None) -> str:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-esmfn-")
    zip_bytes = _make_zip(code)
    deadline = time.monotonic() + 40.0
    last_err: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                MemorySize=128,
                Environment={"Variables": env or {}},
                Publish=True,
                Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-esmfn"},
            )
            break
        except ClientError as err:
            if err.response["Error"]["Code"] == "InvalidParameterValueException":
                last_err = err
                time.sleep(2)
                continue
            raise
    else:
        assert last_err is not None, "create_function retry loop exited with no captured error"
        raise last_err
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _poll_until(lambda: lam.get_function(FunctionName=name)["Configuration"]["State"], lambda s: s == "Active", timeout_s=60)
    return name


def _create_esm(ctx, event_source_arn: str, function_name: str, **kwargs: Any) -> str:
    lam = ctx.client("lambda")
    resp = lam.create_event_source_mapping(EventSourceArn=event_source_arn, FunctionName=function_name, **kwargs)
    uuid = resp["UUID"]
    ctx.on_cleanup(lambda: lam.delete_event_source_mapping(UUID=uuid))
    _poll_until(
        lambda: lam.get_event_source_mapping(UUID=uuid)["State"],
        lambda s: s in ("Enabled", "Disabled"),
        timeout_s=90,
        interval_s=3,
    )
    return uuid


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
