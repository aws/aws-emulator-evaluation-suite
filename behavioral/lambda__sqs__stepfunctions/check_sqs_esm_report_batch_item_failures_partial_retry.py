"""sqs-esm-report-batch-item-failures-partial-retry."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sqs-esm-report-batch-item-failures-partial-retry"
GROUP = "esm-advanced"
SERVICES = ["lambda", "stepfunctions", "sqs"]

_HANDLER_CODE = """
import boto3, json, os
sqs = boto3.client("sqs")
RESULTS_QUEUE = os.environ["RESULTS_QUEUE_URL"]

def handler(event, context):
    batch_item_failures = []
    for r in event.get("Records", []):
        body = r.get("body", "")
        if "FAIL" in body:
            batch_item_failures.append({"itemIdentifier": r["messageId"]})
            continue
        sqs.send_message(
            QueueUrl=RESULTS_QUEUE,
            MessageBody=json.dumps({"body": body, "messageId": r["messageId"]}),
        )
    return {"batchItemFailures": batch_item_failures}
"""


# timing:real-time — visibility: 10 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """batchItemFailures leaves only the failed message IDs eligible for redelivery."""
    sqs = ctx.client("sqs")
    # SQS event source mappings require the queue's VisibilityTimeout to be >= the
    # Lambda function's Timeout (the poller must be able to hold the message invisible
    # for the whole invocation). Pin the function timeout to fit inside the queue's
    # 10s VisibilityTimeout so the mapping is even accepted.
    queue_visibility_timeout_s = 10
    function_timeout_s = 10
    source = _create_queue(ctx, attrs={"VisibilityTimeout": str(queue_visibility_timeout_s)})
    results = _create_queue(ctx)
    role_arn = _create_lambda_role(ctx)
    fn_name = _create_function(
        ctx, role_arn, _HANDLER_CODE, timeout=function_timeout_s, env={"RESULTS_QUEUE_URL": results["url"]}
    )
    # FunctionResponseTypes must opt in to ReportBatchItemFailures — without it, the
    # poller ignores the returned batchItemFailures list entirely and deletes the
    # WHOLE batch (including the FAIL items) whenever the invocation itself doesn't
    # raise, which would defeat this check's entire premise.
    uuid = _create_esm(
        ctx, source["arn"], fn_name, BatchSize=10, FunctionResponseTypes=["ReportBatchItemFailures"]
    )

    pass_bodies = {"PASS-0", "PASS-1"}
    fail_bodies = {"FAIL-0", "FAIL-1"}
    for body in ["PASS-0", "FAIL-0", "PASS-1", "FAIL-1"]:
        sqs.send_message(QueueUrl=source["url"], MessageBody=body)

    # Wait until at least the two PASS messages have been forwarded downstream.
    seen_pass: set[str] = set()
    deadline = time.monotonic() + 90.0
    while seen_pass != pass_bodies and time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=results["url"], MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for m in resp.get("Messages", []):
            payload = json.loads(m["Body"])
            seen_pass.add(payload["body"])
            sqs.delete_message(QueueUrl=results["url"], ReceiptHandle=m["ReceiptHandle"])
    assert seen_pass == pass_bodies, f"expected {pass_bodies} forwarded, got {seen_pass}"

    # Stop the mapping from continuing to retry the failed items, then inspect the
    # source queue directly: the FAIL messages must still be present (never deleted)
    # while the PASS messages must be gone.
    lam = ctx.client("lambda")
    lam.update_event_source_mapping(UUID=uuid, Enabled=False)
    _poll_until(lambda: lam.get_event_source_mapping(UUID=uuid)["State"], lambda s: s == "Disabled", timeout_s=60)

    # The FAIL messages may still be mid-flight (invisible from the ESM's last poll
    # round) right after we flip Enabled=False, since disabling only stops *new*
    # polls — it does not shorten an already-in-flight message's remaining
    # visibility window. Keep long-polling across a couple of full visibility-timeout
    # cycles instead of stopping at the first empty page, otherwise a transient
    # "nothing visible yet" response is mistaken for "nothing left".
    remaining_bodies: set[str] = set()
    receive_counts: dict[str, int] = {}
    deadline = time.monotonic() + max(60.0, queue_visibility_timeout_s * 4)
    while time.monotonic() < deadline and remaining_bodies != fail_bodies:
        resp = sqs.receive_message(
            QueueUrl=source["url"],
            MaxNumberOfMessages=10,
            WaitTimeSeconds=10,
            AttributeNames=["ApproximateReceiveCount"],
            VisibilityTimeout=1,
        )
        msgs = resp.get("Messages", [])
        for m in msgs:
            remaining_bodies.add(m["Body"])
            receive_counts[m["Body"]] = int(m["Attributes"]["ApproximateReceiveCount"])

    assert remaining_bodies == fail_bodies, f"expected only {fail_bodies} still queued, got {remaining_bodies}"
    for body, count in receive_counts.items():
        assert count >= 1, f"{body} was never delivered before ({count})"


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
    resp = lam.create_event_source_mapping(
        EventSourceArn=event_source_arn,
        FunctionName=function_name,
        Tags={"sim2real:managed": "true"},
        **kwargs,
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
