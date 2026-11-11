"""sqs-esm-mismatched-queue-arn-not-triggered-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sqs-esm-mismatched-queue-arn-not-triggered-negative"
GROUP = "esm-advanced"
SERVICES = ["lambda", "stepfunctions", "sqs"]

_HANDLER_CODE = """
import boto3, json, os
sqs = boto3.client("sqs")
RESULTS_QUEUE = os.environ["RESULTS_QUEUE_URL"]

def handler(event, context):
    for r in event.get("Records", []):
        sqs.send_message(QueueUrl=RESULTS_QUEUE, MessageBody=json.dumps({"body": r["body"]}))
    return {"batchItemFailures": []}
"""


@tags(
    "axis:negative-delivery",
    "cap:c3",
    "concern:data-plane",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """An ESM wired to queue B never fires for messages sent to unrelated queue A."""
    sqs = ctx.client("sqs")
    unwired_queue = _create_queue(ctx)
    wired_queue = _create_queue(ctx)
    results = _create_queue(ctx)
    role_arn = _create_lambda_role(ctx)
    fn_name = _create_function(ctx, role_arn, _HANDLER_CODE, env={"RESULTS_QUEUE_URL": results["url"]})
    _create_esm(ctx, wired_queue["arn"], fn_name, BatchSize=10)

    sqs.send_message(QueueUrl=unwired_queue["url"], MessageBody="should-never-be-consumed")

    # Give the poller ample opportunity; it is simply pointed at the other queue.
    deadline = time.monotonic() + 60.0
    saw_invocation = False
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=results["url"], MaxNumberOfMessages=10, WaitTimeSeconds=5)
        if resp.get("Messages"):
            saw_invocation = True
            break
    assert not saw_invocation, "lambda was invoked for a message sent to a queue the mapping does not watch"

    attrs = sqs.get_queue_attributes(
        QueueUrl=unwired_queue["url"], AttributeNames=["ApproximateNumberOfMessages"]
    )["Attributes"]
    assert int(attrs["ApproximateNumberOfMessages"]) == 1, "the unconsumed message must still be sitting in the queue"

    # Positive control: the same mapping DOES work for the queue it is actually wired to.
    sqs.send_message(QueueUrl=wired_queue["url"], MessageBody="should-be-consumed")
    delivered = None
    deadline = time.monotonic() + 90.0
    while delivered is None and time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=results["url"], MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for m in resp.get("Messages", []):
            delivered = json.loads(m["Body"])
            sqs.delete_message(QueueUrl=results["url"], ReceiptHandle=m["ReceiptHandle"])
    assert delivered is not None, "positive control: mapping never invoked lambda for its own wired queue"
    assert delivered["body"] == "should-be-consumed", f"expected echoed body 'should-be-consumed', got {delivered['body']!r}"


def _resource_tags() -> dict[str, str]:
    return {"sim2real:managed": "true", "sim2real:check": CHECK}


def _resource_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _resource_tags().items()]


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
    url = sqs.create_queue(QueueName=name, Attributes=attributes, tags=_resource_tags())["QueueUrl"]
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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_resource_tags_kv()
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
                Tags=_resource_tags(),
            )
            break
        except ClientError as err:
            if err.response["Error"]["Code"] == "InvalidParameterValueException":
                last_err = err
                time.sleep(2)
                continue
            raise
    else:
        assert last_err is not None, "create_function retry loop exited without ever raising or succeeding"
        raise last_err
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _poll_until(lambda: lam.get_function(FunctionName=name)["Configuration"]["State"], lambda s: s == "Active", timeout_s=60)
    return name


def _create_esm(ctx, event_source_arn: str, function_name: str, **kwargs: Any) -> str:
    lam = ctx.client("lambda")
    resp = lam.create_event_source_mapping(
        EventSourceArn=event_source_arn, FunctionName=function_name, Tags=_resource_tags(), **kwargs
    )
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
