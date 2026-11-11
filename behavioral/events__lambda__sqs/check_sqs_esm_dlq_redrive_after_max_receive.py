"""sqs-esm-dlq-redrive-after-max-receive."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sqs-esm-dlq-redrive-after-max-receive"
GROUP = "event-source-mapping"
SERVICES = ["events", "lambda", "sqs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A message that Lambda always fails to process survives at least its first delivery, and is
    redriven to the source queue's DLQ only once maxReceiveCount is exceeded -- not before."""
    sqs = ctx.client("sqs")
    visibility_timeout = 5
    dlq = _create_queue(ctx)
    # An independent side channel: the source queue's own ESM poller receives the message, not this
    # check, so the only way to observe how many times Lambda was actually invoked for it -- and
    # therefore whether the redrive happened before maxReceiveCount was exceeded -- is to have the
    # handler report each delivery attempt here.
    deliveries = _create_queue(ctx)
    source = _create_queue(
        ctx,
        attrs={
            "VisibilityTimeout": str(visibility_timeout),
            "RedrivePolicy": json.dumps({"deadLetterTargetArn": dlq["arn"], "maxReceiveCount": "2"}),
        },
    )
    role = _create_role(
        ctx,
        [
            {
                "Effect": "Allow",
                "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
                "Resource": source["arn"],
            },
            {
                "Effect": "Allow",
                "Action": ["sqs:SendMessage"],
                "Resource": deliveries["arn"],
            },
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            },
        ],
    )
    # Lambda requires the function's Timeout to be <= the queue's VisibilityTimeout, so pin it to
    # fit inside that window; the handler fails immediately and does no sleeping.
    fn = _create_function(
        ctx,
        role["arn"],
        {"FAIL_MARKER": "ALWAYSFAIL", "RESULT_QUEUE_URL": deliveries["url"]},
        timeout=visibility_timeout,
    )
    _create_esm(
        ctx, source["arn"], fn["name"], batch_size=1, extra={"FunctionResponseTypes": ["ReportBatchItemFailures"]}
    )

    body = "ALWAYSFAIL-payload"
    sqs.send_message(QueueUrl=source["url"], MessageBody=body)

    # Without counting delivery attempts, a target that redrives on the FIRST failed delivery --
    # i.e. one ignoring RedrivePolicy's maxReceiveCount entirely -- would satisfy this check just as
    # well as a correct one: the loop below breaks the moment the DLQ holds anything. The bound
    # asserted after the loop is deliberately the safe one (see there) rather than the exact
    # boundary this check has never measured.
    deadline = time.monotonic() + 150
    dlq_body = None
    delivery_attempts = 0
    while time.monotonic() < deadline and dlq_body is None:
        resp = sqs.receive_message(QueueUrl=dlq["url"], MaxNumberOfMessages=1, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            dlq_body = msg["Body"]
            sqs.delete_message(QueueUrl=dlq["url"], ReceiptHandle=msg["ReceiptHandle"])
        delivery_attempts += _drain_delivery_starts(sqs, deliveries["url"], wait=0)
    # The redrive can race the handler's own "start" notification for the delivery that triggered
    # it, so give any still-in-flight delivery record a bounded window to arrive before counting.
    drain_deadline = time.monotonic() + 15
    while time.monotonic() < drain_deadline:
        got = _drain_delivery_starts(sqs, deliveries["url"], wait=3)
        if got == 0:
            break
        delivery_attempts += got
    assert dlq_body == body, f"expected the always-failing message to be redriven to the DLQ, got {dlq_body!r}"
    # This is the assertion that makes the redrive threshold falsifiable, and it has to live here
    # rather than inside the loop above: the loop breaks the moment the DLQ holds anything, so an
    # in-loop check on the same condition would sit after the break and never run for the very case
    # it targets. AWS moves a message once its ReceiveCount *exceeds* maxReceiveCount, so with
    # maxReceiveCount=2 the move happens on the third delivery -- but rather than pin a boundary this
    # check never measured, it asserts only that the message survived its first delivery, which is
    # already enough to fail a redrive-immediately target and cannot false-fail a correct one on an
    # off-by-one.
    assert delivery_attempts >= 2, (
        f"message reached the DLQ after {delivery_attempts} delivery attempt(s); maxReceiveCount=2 "
        f"requires it to survive at least the first"
    )

    deadline = time.monotonic() + 30
    remaining = None
    while time.monotonic() < deadline:
        attrs = sqs.get_queue_attributes(
            QueueUrl=source["url"],
            AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
        )["Attributes"]
        remaining = int(attrs["ApproximateNumberOfMessages"]) + int(attrs["ApproximateNumberOfMessagesNotVisible"])
        if remaining == 0:
            break
        time.sleep(3)
    assert remaining == 0, f"message is still present on the source queue after being redriven to the DLQ: {remaining}"


# ===== helpers =====

_LAMBDA_SOURCE = '''
import boto3
import json
import os
import time

_sqs = boto3.client("sqs")
RESULT_QUEUE_URL = os.environ.get("RESULT_QUEUE_URL")
FAIL_MARKER = os.environ.get("FAIL_MARKER", "__NEVER_MATCH__")
SLEEP_SECONDS = float(os.environ.get("SLEEP_SECONDS", "0"))


def handler(event, context):
    records = event.get("Records", [])
    if RESULT_QUEUE_URL:
        _sqs.send_message(
            QueueUrl=RESULT_QUEUE_URL,
            MessageBody=json.dumps({
                "phase": "start",
                "ts": time.time(),
                "message_ids": [r["messageId"] for r in records],
                "batch_size": len(records),
            }),
        )
    if SLEEP_SECONDS:
        time.sleep(SLEEP_SECONDS)
    batch_item_failures = []
    delivered = []
    for r in records:
        body = r.get("body", "")
        if FAIL_MARKER and FAIL_MARKER in body:
            batch_item_failures.append({"itemIdentifier": r["messageId"]})
            continue
        delivered.append({
            "messageId": r["messageId"],
            "body": body,
            "groupId": r.get("attributes", {}).get("MessageGroupId"),
        })
    if RESULT_QUEUE_URL:
        _sqs.send_message(
            QueueUrl=RESULT_QUEUE_URL,
            MessageBody=json.dumps({
                "phase": "done",
                "ts": time.time(),
                "delivered": delivered,
                "failed_ids": [f["itemIdentifier"] for f in batch_item_failures],
                "batch_size": len(records),
            }),
        )
    return {"batchItemFailures": batch_item_failures}
'''


def _name(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"sim2real-esl-{kind}-")


def _zip_bytes(source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("handler.py", source)
    return buf.getvalue()


def _create_role(ctx: Any, statements: list[dict[str, Any]]) -> dict[str, str]:
    iam = ctx.client("iam")
    name = _name(ctx, "role")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    if statements:
        iam.put_role_policy(
            RoleName=name,
            PolicyName="inline",
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"))
    return {"name": name, "arn": arn}


def _create_function(ctx: Any, role_arn: str, env: dict[str, str], timeout: int = 30) -> dict[str, str]:
    lam = ctx.client("lambda")
    name = _name(ctx, "fn")
    code = _zip_bytes(_LAMBDA_SOURCE)
    resp = None
    last_err = None
    # IAM role propagation: retry CreateFunction on its propagation error for up to 60 s.
    left = ctx.time_left()
    deadline = time.monotonic() + (60.0 if left is None else max(1.0, min(60.0, left - 5.0)))
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="handler.handler",
                Code={"ZipFile": code},
                Timeout=timeout,
                Environment={"Variables": env},
            )
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            time.sleep(2)
    if resp is None:
        raise AssertionError(f"function creation never succeeded (role propagation?): {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    deadline = time.monotonic() + 90
    state = None
    while time.monotonic() < deadline:
        state = lam.get_function(FunctionName=name)["Configuration"]["State"]
        if state == "Active":
            break
        time.sleep(3)
    if state != "Active":
        raise AssertionError(f"function {name} never became Active (last state {state})")
    return {"name": name, "arn": resp["FunctionArn"]}


def _create_queue(ctx: Any, fifo: bool = False, attrs: dict[str, str] | None = None) -> dict[str, str]:
    sqs = ctx.client("sqs")
    name = _name(ctx, "q")
    attributes = dict(attrs or {})
    if fifo:
        name += ".fifo"
        attributes["FifoQueue"] = "true"
    kwargs: dict[str, Any] = {"QueueName": name}
    if attributes:
        kwargs["Attributes"] = attributes
    url = sqs.create_queue(**kwargs)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


def _drain_delivery_starts(sqs: Any, queue_url: str, wait: int) -> int:
    """Drain the handler's delivery-start notifications and return how many were seen."""
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait)
    messages = resp.get("Messages", [])
    count = 0
    for msg in messages:
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        if json.loads(msg["Body"]).get("phase") == "start":
            count += 1
    return count


def _wait_for_esm_state(ctx: Any, uuid_: str, state: str, timeout_s: int = 120) -> str:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_event_source_mapping(UUID=uuid_)["State"]
        if last == state:
            return last
        time.sleep(3)
    raise AssertionError(f"ESM {uuid_} never reached {state!r}, last state was {last!r}")


def _create_esm(
    ctx: Any, source_arn: str, function_name: str, batch_size: int = 1, extra: dict[str, Any] | None = None
) -> str:
    lam = ctx.client("lambda")
    kwargs: dict[str, Any] = dict(
        EventSourceArn=source_arn, FunctionName=function_name, BatchSize=batch_size, Enabled=True
    )
    if extra:
        kwargs.update(extra)
    uuid_ = lam.create_event_source_mapping(**kwargs)["UUID"]
    ctx.on_cleanup(lambda: lam.delete_event_source_mapping(UUID=uuid_))
    _wait_for_esm_state(ctx, uuid_, "Enabled")
    return uuid_


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
