"""sqs-esm-disabled-mapping-stops-delivery."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags

CHECK = "sqs-esm-disabled-mapping-stops-delivery"
GROUP = "permission-boundary"
SERVICES = ["events", "lambda", "sqs"]

_TAGS = {"sim2real:managed": "true", "sim2real:check": CHECK}


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """Disabling an event source mapping halts further Lambda invocations even as new messages arrive; delivery works while enabled (in-file control)."""
    source = _create_queue(ctx)
    result = _create_queue(ctx)
    role = _create_role(
        ctx,
        [
            {
                "Effect": "Allow",
                "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
                "Resource": source["arn"],
            },
            {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": result["arn"]},
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            },
        ],
    )
    fn = _create_function(ctx, role["arn"], {"RESULT_QUEUE_URL": result["url"]})
    uuid_ = _create_esm(ctx, source["arn"], fn["name"], batch_size=1)

    sqs = ctx.client("sqs")

    # Positive control: the mapping delivers messages while it is enabled. Measure how long
    # that took (L) so the negative leg below can hold absence for a multiple of the real,
    # observed delivery latency instead of a guessed constant.
    control_start = time.monotonic()
    sqs.send_message(QueueUrl=source["url"], MessageBody="before-disable")
    events = _drain(ctx, result["url"], lambda evs: any(e.get("phase") == "done" for e in evs), timeout_s=90)
    positive_latency_s = time.monotonic() - control_start
    delivered_before = [d["body"] for e in events if e.get("phase") == "done" for d in e.get("delivered", [])]
    assert "before-disable" in delivered_before, "positive control failed: message was not delivered while the mapping was enabled"

    lam = ctx.client("lambda")
    lam.update_event_source_mapping(UUID=uuid_, Enabled=False)
    _wait_for_esm_state(ctx, uuid_, "Disabled")
    # The mapping's State flips to "Disabled" before the underlying poller threads have
    # necessarily wound down, so an in-flight poll can still race the disable. Bound that
    # settle period with a freeze detector (repeated reads asserting the state does not flip
    # back off "Disabled") instead of a blind sleep, so a target that regresses mid-window is
    # itself caught rather than silently waited past.
    _hold_state(ctx, uuid_, "Disabled", hold_s=30, interval_s=5)

    sqs.send_message(QueueUrl=source["url"], MessageBody="after-disable")
    # Hold absence for >=3x the measured positive-control latency,
    # with a short floor, rather than a guessed constant.
    negative_window_s = max(15.0, 3 * positive_latency_s)
    after_events = _drain(ctx, result["url"], lambda evs: False, timeout_s=negative_window_s)
    delivered_after = [d["body"] for e in after_events if e.get("phase") == "done" for d in e.get("delivered", [])]
    assert "after-disable" not in delivered_after, "a disabled event source mapping still invoked Lambda for a new message"

    # A poll that raced the disable may hold the message invisible until its visibility timeout
    # ends; it is still on the queue either way, so count both.
    attrs = sqs.get_queue_attributes(
        QueueUrl=source["url"],
        AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
    )["Attributes"]
    on_queue = int(attrs["ApproximateNumberOfMessages"]) + int(attrs["ApproximateNumberOfMessagesNotVisible"])
    assert on_queue >= 1, "the unconsumed message unexpectedly vanished from the source queue"


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
    tags_kv = [{"Key": k, "Value": v} for k, v in _TAGS.items()]
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust), Tags=tags_kv)["Role"]["Arn"]
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
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="handler.handler",
                Code={"ZipFile": code},
                Timeout=timeout,
                Environment={"Variables": env},
                Tags=dict(_TAGS),
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
    kwargs: dict[str, Any] = {"QueueName": name, "tags": dict(_TAGS)}
    if attributes:
        kwargs["Attributes"] = attributes
    url = sqs.create_queue(**kwargs)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


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


def _hold_state(ctx: Any, uuid_: str, state: str, hold_s: float, interval_s: float) -> None:
    """Bounded retry with a deadline: repeatedly re-read the ESM state for `hold_s` seconds,
    asserting it stays `state` throughout. Used as a settle window that also doubles as a
    freeze detector -- a target that flips back off `state` mid-window is caught, not silently
    waited past."""
    lam = ctx.client("lambda")
    deadline = time.monotonic() + hold_s
    while time.monotonic() < deadline:
        seen = lam.get_event_source_mapping(UUID=uuid_)["State"]
        assert seen == state, f"ESM {uuid_} left {state!r} during the settle window (observed {seen!r})"
        time.sleep(interval_s)


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


def _drain(ctx: Any, queue_url: str, predicate, timeout_s: float) -> list[dict[str, Any]]:
    sqs = ctx.client("sqs")
    events: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            try:
                events.append(json.loads(msg["Body"]))
            except (ValueError, json.JSONDecodeError):
                pass
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        if predicate(events):
            return events
    return events


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
