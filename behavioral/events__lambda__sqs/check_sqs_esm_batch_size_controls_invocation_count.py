"""sqs-esm-batch-size-controls-invocation-count."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sqs-esm-batch-size-controls-invocation-count"
GROUP = "event-source-mapping"
SERVICES = ["events", "lambda", "sqs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """Lambda invocation batch size never exceeds the ESM BatchSize and reaches it once enough messages are queued."""
    batch_size = 5
    total_messages = 15

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
    _create_esm(ctx, source["arn"], fn["name"], batch_size=batch_size)

    sqs = ctx.client("sqs")
    for i in range(total_messages):
        sqs.send_message(QueueUrl=source["url"], MessageBody=f"msg-{i}")

    delivered_total = {"n": 0}

    def _enough(evs: list[dict[str, Any]]) -> bool:
        delivered_total["n"] = sum(len(e.get("delivered", [])) for e in evs if e.get("phase") == "done")
        return delivered_total["n"] >= total_messages

    events = _drain(ctx, result["url"], _enough, timeout_s=150)

    starts = [e for e in events if e.get("phase") == "start"]
    assert starts, "no invocations observed"
    batch_sizes = [e["batch_size"] for e in starts]
    assert all(b <= batch_size for b in batch_sizes), (
        f"observed an invocation batch larger than the configured BatchSize={batch_size}: {batch_sizes}"
    )
    assert max(batch_sizes) == batch_size, (
        f"expected at least one invocation to reach the full BatchSize={batch_size}, saw max {max(batch_sizes)}"
    )
    assert delivered_total["n"] >= total_messages, (
        f"only {delivered_total['n']} of {total_messages} sent messages were delivered to Lambda"
    )


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


_MANAGED_TAG_KEY = "sim2real:managed"
_RESOURCE_PREFIX = "sim2real-esl"


def _resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _RESOURCE_PREFIX}


def _name(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_RESOURCE_PREFIX}-{kind}-")


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
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": k, "Value": v} for k, v in _resource_tags().items()],
    )["Role"]["Arn"]
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
    ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
    create_deadline = time.monotonic() + min(60.0, ctx.time_left() or 60.0)
    while time.monotonic() < create_deadline:
        try:
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="handler.handler",
                Code={"ZipFile": code},
                Timeout=timeout,
                Environment={"Variables": env},
                Tags=dict(_resource_tags()),
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
    kwargs["tags"] = _resource_tags()
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
