"""esm-on-sse-kms-queue-withholds-invocation-until-the-role-can-decrypt."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "esm-on-sse-kms-queue-withholds-invocation-until-the-role-can-decrypt"
GROUP = "esm"
SERVICES = ["kms", "lambda", "sqs"]


@tags(
    "axis:negative-delivery",
    "concern:data-plane",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """An ESM on an SSE-KMS queue whose role lacks kms:Decrypt never invokes the function and keeps
    the message queued past two visibility timeouts while an SSE-SQS twin queue on the same function
    delivers; granting kms:Decrypt delivers the same message.
    """
    sqs = ctx.client("sqs")
    kms = ctx.client("kms")
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")

    key_arn = _create_key(ctx, kms)
    queue_url, queue_arn = _create_queue(ctx, sqs, {"KmsMasterKeyId": key_arn})
    twin_url, twin_arn = _create_queue(ctx, sqs, {"SqsManagedSseEnabled": "true"})
    role_arn, role_name = _create_role(ctx, iam, [queue_arn, twin_arn])
    fn_name = _create_function(ctx, lam, role_arn)

    uuids = []
    for arn in (twin_arn, queue_arn):
        esm = lam.create_event_source_mapping(EventSourceArn=arn, FunctionName=fn_name, BatchSize=1)
        uuids.append(esm["UUID"])
        ctx.on_cleanup(lambda u=esm["UUID"]: _delete_esm(lam, u))
    for u in uuids:
        _wait_esm_state(ctx, lam, u, "Enabled")

    marker = ctx.unique_name("sim2real-behav-kmsnodec-")
    twin_marker = ctx.unique_name("sim2real-behav-ssesqs-")
    sqs.send_message(QueueUrl=twin_url, MessageBody=twin_marker)
    sqs.send_message(QueueUrl=queue_url, MessageBody=marker)

    # Contrast: the same function, through the same kind of mapping, receives an SSE-SQS message,
    # so the KMS-queue absence below is not explained by a mapping that delivers nothing.
    assert _wait_invocation_logged(ctx, logs, fn_name, twin_marker, timeout_s=180.0), (
        f"the SSE-SQS twin's message {twin_marker!r} never reached the function -- without a "
        "delivering twin the withheld invocation below proves nothing"
    )

    # The two depth counters are approximate and settle independently, so the wait accepts the
    # first reading where both agree the message is in flight.
    _wait_message_held(ctx, sqs, queue_url, timeout_s=90.0)
    hold_s = max(_MIN_HOLD_S, 2 * _VISIBILITY_TIMEOUT_S)
    hold_until = time.monotonic() + hold_s
    while True:
        # The depth attributes are approximate and can read 0/0 for an instant while the message
        # moves between in-flight and visible; a zero is confirmed by fresh reads before it fails.
        reads = [_queue_depth(sqs, queue_url)]
        while _depth(reads[-1]) == 0 and len(reads) < _ZERO_CONFIRM_READS:
            time.sleep(1)
            reads.append(_queue_depth(sqs, queue_url))
        assert _depth(reads[-1]) >= 1, (
            f"the undecryptable message must stay in the queue throughout the {hold_s:.0f}s hold; "
            f"queue depth read zero {len(reads)} times running: {reads!r}"
        )
        seen = _marker_logged(logs, fn_name, marker)
        assert not seen, (
            f"the function must never be invoked with {marker!r} while its role cannot decrypt "
            f"the queue's key, but its log carries it: {seen!r}"
        )
        if time.monotonic() >= hold_until:
            break
        time.sleep(2)

    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sim2real-decrypt",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "kms:Decrypt", "Resource": key_arn}],
        }),
    )
    _wait_queue_drained(ctx, sqs, queue_url, timeout_s=180.0)
    delivered = _wait_invocation_logged(ctx, logs, fn_name, marker, timeout_s=60.0)
    assert delivered, (
        f"control: after granting kms:Decrypt the function must be invoked with the held message "
        f"{marker!r}; no matching log line was found -- without this leg the withheld invocation "
        "above proves nothing"
    )


# Short enough that two full visibility cycles fit the check's budget; the function's Timeout
# stays below it, as an SQS mapping requires.
_VISIBILITY_TIMEOUT_S = 5
_FUNCTION_TIMEOUT_S = 3
_MIN_HOLD_S = 12.0
_ZERO_CONFIRM_READS = 4


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _depth(attrs: dict[str, str]) -> int:
    return int(attrs["ApproximateNumberOfMessages"]) + int(attrs["ApproximateNumberOfMessagesNotVisible"])


def _queue_depth(sqs, queue_url) -> dict[str, str]:
    return sqs.get_queue_attributes(
        QueueUrl=queue_url,
        AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
    )["Attributes"]


def _marker_logged(logs, fn_name, marker) -> list[str]:
    """Every log line in /aws/lambda/<fn_name> that carries ``marker``."""
    try:
        pages = logs.get_paginator("filter_log_events").paginate(
            logGroupName=f"/aws/lambda/{fn_name}", filterPattern=f'"{marker}"')
        return [e["message"] for page in pages for e in page.get("events", [])]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return []
        raise


def _wait_message_held(ctx, sqs, queue_url, *, timeout_s) -> dict[str, str]:
    """Poll until the queue reports the message in flight and none visible; return attributes."""
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        attrs = sqs.get_queue_attributes(
            QueueUrl=queue_url,
            AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
        )["Attributes"]
        last = attrs
        if (
            attrs["ApproximateNumberOfMessagesNotVisible"] != "0"
            and attrs["ApproximateNumberOfMessages"] == "0"
        ):
            return attrs
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError("message to become held (in flight, not visible): the run budget ended first; not graded")
    raise AssertionError(f"message never became held (in flight, not visible) within {timeout_s}s (last={last!r})")


def _wait_queue_drained(ctx, sqs, queue_url, *, timeout_s) -> None:
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        attrs = sqs.get_queue_attributes(
            QueueUrl=queue_url,
            AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
        )["Attributes"]
        last = attrs
        if attrs["ApproximateNumberOfMessages"] == "0" and attrs["ApproximateNumberOfMessagesNotVisible"] == "0":
            return
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError("queue to drain after granting decrypt: the run budget ended first; not graded")
    raise AssertionError(f"queue never drained within {timeout_s}s after granting decrypt (last={last!r})")


def _wait_invocation_logged(ctx, logs, fn_name, marker, *, timeout_s) -> bool:
    """Poll /aws/lambda/<fn_name> log streams for a line containing ``marker``, bounded."""
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    while time.monotonic() < deadline:
        try:
            streams = logs.describe_log_streams(
                logGroupName=f"/aws/lambda/{fn_name}", orderBy="LastEventTime", descending=True, limit=5
            )["logStreams"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            streams = []
        for stream in streams:
            events = logs.get_log_events(
                logGroupName=f"/aws/lambda/{fn_name}", logStreamName=stream["logStreamName"]
            )["events"]
            if any(marker in e["message"] for e in events):
                return True
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f"an invocation logging {marker!r}: the run budget ended first; not graded")
    return False


def _wait_esm_state(ctx, lam, uuid: str, want: str, *, timeout_s=120.0) -> None:
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        last = lam.get_event_source_mapping(UUID=uuid).get("State")
        if last == want:
            return
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f"ESM {uuid} to reach State={want!r}: the run budget ended first; not graded")
    raise AssertionError(f"ESM {uuid} never reached State={want!r} within {timeout_s}s (last={last!r})")


def _delete_esm(lam, uuid: str, *, timeout_s=60.0) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            lam.delete_event_source_mapping(UUID=uuid)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceInUseException" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _create_key(ctx, kms) -> str:
    key = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kmsesm-key-"),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key["KeyId"], PendingWindowInDays=7))
    return key["Arn"]


def _create_queue(ctx, sqs, encryption: dict[str, str]) -> tuple[str, str]:
    name = ctx.unique_name("sim2real-behav-kmsesm-q-")
    url = sqs.create_queue(
        QueueName=name,
        Attributes={"VisibilityTimeout": str(_VISIBILITY_TIMEOUT_S), **encryption},
        tags={"sim2real": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_role(ctx, iam, queue_arns: list[str]) -> tuple[str, str]:
    name = ctx.unique_name("sim2real-behav-kmsesm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    # Deliberately no kms:Decrypt.
    iam.put_role_policy(
        RoleName=name,
        PolicyName="inline",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                    "Resource": "arn:aws:logs:*:*:*",
                },
                {
                    "Effect": "Allow",
                    "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
                    "Resource": queue_arns,
                },
            ],
        }),
    )
    ctx.on_cleanup(lambda: _delete_role(iam, name))
    return resp["Role"]["Arn"], name


def _delete_role(iam, name: str) -> None:
    for pname in iam.list_role_policies(RoleName=name)["PolicyNames"]:
        iam.delete_role_policy(RoleName=name, PolicyName=pname)
    iam.delete_role(RoleName=name)


def _create_function(ctx, lam, role_arn: str) -> str:
    name = ctx.unique_name("sim2real-behav-kmsesm-fn-")
    code = textwrap.dedent(
        """
        def lambda_handler(event, context):
            for record in event.get("Records", []):
                print("forwarded:" + record["body"])
            return {"records": len(event.get("Records", []))}
        """
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", code)

    kwargs: dict[str, Any] = {
        "FunctionName": name,
        "Runtime": "python3.12",
        "Role": role_arn,
        "Handler": "lambda_function.lambda_handler",
        "Code": {"ZipFile": buf.getvalue()},
        "Timeout": _FUNCTION_TIMEOUT_S,
        "MemorySize": 128,
        "Tags": {"sim2real": CHECK},
    }
    # Registered before the create, so LIFO runs delete_function first and this reap second --
    # catching a buffered log flush that recreates the group right after the delete.
    _reap_log_group(ctx, name)

    deadline = time.monotonic() + _budget_s(ctx, 30)
    last_err = None
    while time.monotonic() < deadline:
        try:
            lam.create_function(**kwargs)
            break
        except ClientError as exc:
            if "cannot be assumed" in str(exc) or exc.response["Error"]["Code"] == "InvalidParameterValueException":
                last_err = exc
                time.sleep(3)
                continue
            raise
    else:
        if _budget_spent(ctx):
            raise TimeoutError(f"CreateFunction {name} to be accepted: the run budget ended first; not graded")
        raise last_err or RuntimeError(f"failed to create function {name}")

    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_function_active(ctx, lam, name)
    return name


def _reap_log_group(ctx, fn_name: str) -> None:
    def _cleanup():
        logs = ctx.client("logs")
        deadline = time.monotonic() + 20.0
        while True:
            try:
                logs.delete_log_group(logGroupName=f"/aws/lambda/{fn_name}")
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
            if time.monotonic() > deadline:
                return
            time.sleep(4)

    ctx.on_cleanup(_cleanup)


def _wait_function_active(ctx, lam, fn_name: str, *, timeout_s=60.0) -> None:
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=fn_name)
        last = cfg.get("State")
        if last == "Active":
            return
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"function {fn_name} to become Active: the run budget ended first; not graded")
    raise AssertionError(f"function {fn_name} never became Active within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
