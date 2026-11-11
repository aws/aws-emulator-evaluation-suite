"""default-target-payload-is-the-sqs-source-record."""
from __future__ import annotations

import hashlib
import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "default-target-payload-is-the-sqs-source-record"
GROUP = "data-plane"
SERVICES = ["pipes"]

_RES_TAGS = {"sim2real": CHECK}


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:eventing", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """With no TargetParameters, a pipe delivers the SQS source record, not the bare body:
    messageId, body, md5OfBody, messageAttributes and the eventSource/ARN/region match the source.
    """
    sqs = ctx.client("sqs")
    src_url, src_arn = _create_queue(ctx, "sim2real-pipes-env-src-")
    tgt_url, tgt_arn = _create_queue(ctx, "sim2real-pipes-env-dst-")
    role_arn = _create_pipe_role(ctx, _sqs_pipe_statements([src_arn], [tgt_arn]))

    name = ctx.unique_name("sim2real-pipes-env-")
    _create_pipe_with_retry(
        ctx,
        Name=name,
        RoleArn=role_arn,
        Source=src_arn,
        SourceParameters={"SqsQueueParameters": {"BatchSize": 1}},
        Target=tgt_arn,
        DesiredState="RUNNING",
        Tags=_RES_TAGS,
    )
    _wait_state(ctx, name, {"RUNNING"})

    body = f"envelope-{uuid.uuid4().hex}"
    sent = sqs.send_message(
        QueueUrl=src_url,
        MessageBody=body,
        MessageAttributes={"flavour": {"DataType": "String", "StringValue": "plain"}},
    )

    msg = _receive_until(ctx, tgt_url, body)
    payload = json.loads(msg["Body"])
    assert isinstance(payload, dict), (
        f"target body should be one JSON object (the source record), got {type(payload).__name__}: {msg['Body'][:300]!r}"
    )
    assert payload.get("body") == body, f"record body {payload.get('body')!r} != sent body {body!r}"
    assert payload.get("messageId") == sent["MessageId"], (
        f"record messageId {payload.get('messageId')!r} is not the id SendMessage returned"
    )
    expected_md5 = hashlib.md5(body.encode()).hexdigest()
    assert payload.get("md5OfBody") == expected_md5 == sent["MD5OfMessageBody"], (
        f"md5OfBody {payload.get('md5OfBody')!r}, expected {expected_md5!r}"
    )
    assert payload.get("eventSource") == "aws:sqs", f"eventSource was {payload.get('eventSource')!r}"
    assert payload.get("eventSourceARN") == src_arn, (
        f"eventSourceARN does not name the source queue (shape {str(payload.get('eventSourceARN'))[:12]!r}...)"
    )
    assert payload.get("awsRegion") == ctx.region, f"awsRegion {payload.get('awsRegion')!r} != {ctx.region!r}"
    attrs = payload.get("messageAttributes") or {}
    flavour = attrs.get("flavour") or {}
    assert flavour.get("stringValue") == "plain" and flavour.get("dataType") == "String", (
        f"message attribute did not ride along: messageAttributes={attrs!r}"
    )
    sys_attrs = payload.get("attributes") or {}
    assert sys_attrs.get("ApproximateReceiveCount") == "1", (
        f"attributes.ApproximateReceiveCount was {sys_attrs.get('ApproximateReceiveCount')!r}, expected '1'"
    )
    assert "receiptHandle" in payload and payload["receiptHandle"], "record carries no receiptHandle"

    _delete_pipe_and_wait(ctx, name)


def _error(fn) -> tuple[str, str]:
    """(Error.Code, Error.Message) that ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _create_queue(ctx, prefix: str, attributes: dict | None = None) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    kwargs = {"QueueName": ctx.unique_name(prefix), "tags": dict(_RES_TAGS)}
    if attributes:
        kwargs["Attributes"] = attributes
    url = sqs.create_queue(**kwargs)["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_queue(ctx, url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _delete_queue(ctx, url: str) -> None:
    try:
        ctx.client("sqs").delete_queue(QueueUrl=url)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist"):
            raise


def _create_pipe_role(ctx, statements: list[dict]) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-pipes-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "pipes.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": k, "Value": v} for k, v in _RES_TAGS.items()],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="pipe-access",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="pipe-access"))
    # IAM propagation exposes no pollable condition; the bounded retry in
    # _create_pipe_with_retry rides it out on first use.
    return role_arn


def _sqs_pipe_statements(source_arns: list[str], target_arns: list[str]) -> list[dict]:
    return [
        {
            "Effect": "Allow",
            "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
            "Resource": source_arns,
        },
        {"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": target_arns},
    ]


def _create_pipe_with_retry(ctx, timeout_s: float = 90.0, **kwargs) -> dict:
    """CreatePipe, retrying only while the fresh execution role is still propagating."""
    pipes = ctx.client("pipes")
    left = ctx.time_left()
    if left is not None:
        timeout_s = max(1.0, min(timeout_s, left - 10.0))
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            resp = pipes.create_pipe(**kwargs)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("ValidationException", "AccessDeniedException") and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise
    name = kwargs["Name"]
    ctx.on_cleanup(lambda: _delete_pipe_quiet(ctx, name))
    return resp


def _delete_pipe_quiet(ctx, name: str) -> None:
    """Backstop teardown: issue DeletePipe, riding out a transition in flight."""
    pipes = ctx.client("pipes")
    deadline = time.monotonic() + 45.0
    while True:
        try:
            pipes.delete_pipe(Name=name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NotFoundException":
                return
            if code == "ConflictException" and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise


def _delete_pipe_and_wait(ctx, name: str, timeout_s: float = 180.0) -> None:
    """Inline verified teardown: delete the pipe and poll until DescribePipe is NotFound."""
    pipes = ctx.client("pipes")
    _delete_pipe_quiet(ctx, name)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            pipes.describe_pipe(Name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        time.sleep(3)
    raise AssertionError(f"pipe {name} was still present {timeout_s:.0f}s after DeletePipe")


def _wait_state(ctx, name: str, states: set[str], timeout_s: float = 180.0) -> dict:
    pipes = ctx.client("pipes")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        desc = pipes.describe_pipe(Name=name)
        last = desc["CurrentState"]
        if last in states:
            return desc
        time.sleep(3)
    raise AssertionError(f"pipe {name} never reached {sorted(states)}; last CurrentState was {last!r}")


def _receive_all(ctx, url: str, window_s: float) -> list[dict]:
    """Drain every message visible on ``url`` for ``window_s`` seconds, deleting each."""
    sqs = ctx.client("sqs")
    out: list[dict] = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5, MessageAttributeNames=["All"]
        )
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
            out.append(msg)
    return out


def _receive_until(ctx, url: str, marker: str, timeout_s: float = 120.0) -> dict:
    """Poll ``url`` until a message whose body carries ``marker`` arrives; return it."""
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    seen: list[str] = []
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5, MessageAttributeNames=["All"]
        )
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
            if marker in msg["Body"]:
                return msg
            seen.append(msg["Body"][:200])
    raise AssertionError(f"no message carrying {marker!r} reached the queue within {timeout_s:.0f}s; saw {seen!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
