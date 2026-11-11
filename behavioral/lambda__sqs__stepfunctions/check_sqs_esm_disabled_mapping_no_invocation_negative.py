"""sqs-esm-disabled-mapping-no-invocation-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sqs-esm-disabled-mapping-no-invocation-negative"
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


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A mapping created with Enabled=False never invokes and the source queue polls to one
    visible message; re-enabled, it delivers that message and the queue polls to 0."""
    sqs = ctx.client("sqs")
    source = _create_queue(ctx)
    results = _create_queue(ctx)
    role_arn = _create_lambda_role(ctx)
    fn_name = _create_function(ctx, role_arn, _HANDLER_CODE, env={"RESULTS_QUEUE_URL": results["url"]})
    uuid = _create_esm(ctx, source["arn"], fn_name, BatchSize=10, Enabled=False)
    lam = ctx.client("lambda")
    state = lam.get_event_source_mapping(UUID=uuid)["State"]
    assert state == "Disabled", f"mapping created with Enabled=False reported state {state!r}"

    sqs.send_message(QueueUrl=source["url"], MessageBody="parked-while-disabled")

    deadline = time.monotonic() + 45.0
    saw_invocation = False
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=results["url"], MaxNumberOfMessages=10, WaitTimeSeconds=5)
        if resp.get("Messages"):
            saw_invocation = True
            break
    assert not saw_invocation, "lambda was invoked even though the event source mapping is disabled"

    # the message must remain unconsumed while the mapping is disabled; the counter can lag
    # up to a minute (SQS GetQueueAttributes docs), so it is polled, not read once
    _poll_until(
        lambda: sqs.get_queue_attributes(QueueUrl=source["url"], AttributeNames=["ApproximateNumberOfMessages"])["Attributes"],
        lambda a: int(a["ApproximateNumberOfMessages"]) == 1,
        timeout_s=90.0,
        budget_s=_budget_s(ctx, 90.0),
    )

    # Positive control: re-enable the very same mapping and confirm it now works.
    lam.update_event_source_mapping(UUID=uuid, Enabled=True)
    _poll_until(lambda: lam.get_event_source_mapping(UUID=uuid)["State"], lambda s: s == "Enabled", timeout_s=60)

    delivered = None
    deadline = time.monotonic() + 90.0
    while delivered is None and time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=results["url"], MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for m in resp.get("Messages", []):
            delivered = json.loads(m["Body"])
            sqs.delete_message(QueueUrl=results["url"], ReceiptHandle=m["ReceiptHandle"])
    assert delivered is not None, "positive control: re-enabling the mapping never resulted in an invocation"
    assert delivered["body"] == "parked-while-disabled"

    final = _poll_until(
        lambda: sqs.get_queue_attributes(QueueUrl=source["url"], AttributeNames=["ApproximateNumberOfMessages"])["Attributes"],
        lambda a: int(a["ApproximateNumberOfMessages"]) == 0,
        timeout_s=90.0,
        budget_s=_budget_s(ctx, 90.0),
    )
    assert int(final["ApproximateNumberOfMessages"]) == 0


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float = 2.0, budget_s: float | None = None) -> Any:
    """Poll until predicate holds; a stop forced by the runner's budget, short of timeout_s, is no verdict."""
    start = time.monotonic()
    deadline = start + (timeout_s if budget_s is None else min(timeout_s, budget_s))
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if budget_s is not None and budget_s < timeout_s:
        raise TimeoutError(
            f"the check's time budget ran out after {time.monotonic() - start:.1f}s, before the "
            f"{timeout_s}s wait ended (last={last!r}); not graded"
        )
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
    url = sqs.create_queue(QueueName=name, Attributes=attributes, tags={"sim2real:managed": "true"})["QueueUrl"]
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
        assert last_err is not None
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
