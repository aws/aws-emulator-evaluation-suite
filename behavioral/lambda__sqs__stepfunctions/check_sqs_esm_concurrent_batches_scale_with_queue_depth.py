"""sqs-esm-concurrent-batches-scale-with-queue-depth."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sqs-esm-concurrent-batches-scale-with-queue-depth"
GROUP = "esm-advanced"
SERVICES = ["lambda", "stepfunctions", "sqs"]

_HANDLER_CODE = """
import boto3, json, os, time
sqs = boto3.client("sqs")
RESULTS_QUEUE = os.environ["RESULTS_QUEUE_URL"]
SLEEP_S = float(os.environ.get("SLEEP_S", "3"))

def handler(event, context):
    start = time.time()
    time.sleep(SLEEP_S)
    end = time.time()
    for r in event.get("Records", []):
        sqs.send_message(
            QueueUrl=RESULTS_QUEUE,
            MessageBody=json.dumps({"body": r["body"], "start": start, "end": end}),
        )
    return {"batchItemFailures": []}
"""

MESSAGE_COUNT = 30
FUNCTION_SLEEP_S = 3


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A deep standard queue causes the ESM to run multiple Lambda batches concurrently."""
    sqs = ctx.client("sqs")
    source = _create_queue(ctx)
    results = _create_queue(ctx)
    role_arn = _create_lambda_role(ctx)
    fn_name = _create_function(
        ctx, role_arn, _HANDLER_CODE, timeout=30, env={"RESULTS_QUEUE_URL": results["url"], "SLEEP_S": str(FUNCTION_SLEEP_S)}
    )
    _create_esm(ctx, source["arn"], fn_name, BatchSize=1)

    for i in range(MESSAGE_COUNT):
        sqs.send_message(QueueUrl=source["url"], MessageBody=f"depth-{i}")

    collected: list[dict[str, Any]] = []
    deadline = time.monotonic() + 180.0
    while len(collected) < MESSAGE_COUNT and time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=results["url"], MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for m in resp.get("Messages", []):
            collected.append(json.loads(m["Body"]))
            sqs.delete_message(QueueUrl=results["url"], ReceiptHandle=m["ReceiptHandle"])

    assert len(collected) == MESSAGE_COUNT, f"expected all {MESSAGE_COUNT} messages processed, got {len(collected)}"

    max_concurrency = _max_overlap(collected)
    assert max_concurrency >= 3, (
        f"observed max concurrent invocations={max_concurrency}, expected the ESM to scale out "
        f"batch consumption as queue depth ({MESSAGE_COUNT} messages) grew, not process serially"
    )

    total_wall_clock = max(e["end"] for e in collected) - min(e["start"] for e in collected)
    fully_serial_time = MESSAGE_COUNT * FUNCTION_SLEEP_S
    assert total_wall_clock < fully_serial_time, (
        f"total processing wall clock ({total_wall_clock:.1f}s) was not faster than fully serial "
        f"processing ({fully_serial_time}s), indicating no concurrency"
    )


def _max_overlap(entries: list[dict[str, Any]]) -> int:
    events: list[tuple[float, int]] = []
    for e in entries:
        events.append((e["start"], 1))
        events.append((e["end"], -1))
    events.sort(key=lambda ev: (ev[0], -ev[1]))
    current = 0
    peak = 0
    for _, delta in events:
        current += delta
        peak = max(peak, current)
    return peak


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
        QueueName=name, Attributes=attributes, tags={"sim2real:managed": "true"}
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
                Tags={"sim2real:managed": "true"},
            )
            break
        except ClientError as err:
            if err.response["Error"]["Code"] == "InvalidParameterValueException":
                last_err = err
                time.sleep(2)
                continue
            raise
    else:
        assert last_err is not None, "create_function retry loop exited without a ClientError to raise"
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
