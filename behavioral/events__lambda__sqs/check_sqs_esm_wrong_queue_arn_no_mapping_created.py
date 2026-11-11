"""sqs-esm-wrong-queue-arn-no-mapping-created."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sqs-esm-wrong-queue-arn-no-mapping-created"
GROUP = "permission-boundary"
SERVICES = ["events", "lambda", "sqs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateEventSourceMapping rejects a malformed EventSourceArn and creates no mapping, while a well-formed ARN still succeeds (in-file control)."""
    source = _create_queue(ctx)
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
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            },
        ],
    )
    fn = _create_function(ctx, role["arn"], {})

    # Positive control: a well-formed, existing queue ARN creates a mapping successfully.
    good_uuid = _create_esm(ctx, source["arn"], fn["name"], batch_size=1)
    assert good_uuid, "expected CreateEventSourceMapping on a well-formed queue ARN to return a UUID"

    lam = ctx.client("lambda")
    bad_arn = "not-a-valid-arn-at-all"
    code, message = _error(
        lambda: lam.create_event_source_mapping(
            EventSourceArn=bad_arn, FunctionName=fn["name"], BatchSize=1, Enabled=True
        )
    )
    assert code == "ValidationException", (
        f"expected CreateEventSourceMapping to reject a malformed EventSourceArn with "
        f"ValidationException, got {code!r}"
    )
    expected_message = (
        f"1 validation error detected: Value '{bad_arn}' at 'eventSourceArn' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: "
        r"arn:(aws[a-zA-Z0-9-]*):([a-zA-Z0-9\-])+:((eusc-)?[a-z]{2}((-gov)|(-iso([a-z]?)))?-[a-z]+-\d{1})?:(\d{12})?:(.*)"
    )
    assert message == expected_message, (
        f"expected CreateEventSourceMapping's message {expected_message!r}, got {message!r}"
    )

    mappings = lam.list_event_source_mappings(FunctionName=fn["name"])["EventSourceMappings"]
    assert len(mappings) == 1 and mappings[0]["UUID"] == good_uuid, (
        "a second event source mapping was created despite the malformed EventSourceArn being rejected"
    )


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


def _error(fn) -> tuple[str, str]:
    """Call fn(); return the AWS error (Code, Message) it raised. An unexpected SUCCESS
    raises, so a target that accepts what AWS refuses fails loudly."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _name(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"sim2real-esl-{kind}-")


def _managed_tags() -> dict[str, str]:
    return {"sim2real:managed": "true", "sim2real:prefix": "sim2real-esl"}


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
        Tags=[{"Key": k, "Value": v} for k, v in _managed_tags().items()],
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
                Tags=_managed_tags(),
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
    kwargs: dict[str, Any] = {"QueueName": name, "tags": _managed_tags()}
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
