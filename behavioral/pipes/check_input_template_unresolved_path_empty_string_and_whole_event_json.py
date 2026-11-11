"""input-template-unresolved-path-empty-string-and-whole-event-json."""

from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "input-template-unresolved-path-empty-string-and-whole-event-json"
GROUP = "data-plane"
SERVICES = ["pipes"]

_RES_TAGS = {"sim2real": CHECK}

# <$.body.missing> never resolves (the body carries no "missing" key); <aws.pipes.event.json>
# is the whole-event pseudo path.
_TEMPLATE = '{"unresolved": "<$.body.missing>", "whole_event": <aws.pipes.event.json>}'


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """An InputTemplate path that does not resolve renders as an empty string with its key kept,
    and <aws.pipes.event.json> in the same template renders the whole source record."""
    sqs = ctx.client("sqs")
    src_url, src_arn = _create_queue(ctx, "sim2real-pipes-tpl2-src-")
    tgt_url, tgt_arn = _create_queue(ctx, "sim2real-pipes-tpl2-dst-")
    role_arn = _create_pipe_role(ctx, [src_arn], [tgt_arn])

    name = ctx.unique_name("sim2real-pipes-tpl2-")
    _create_pipe_with_retry(
        ctx,
        Name=name,
        RoleArn=role_arn,
        Source=src_arn,
        SourceParameters={"SqsQueueParameters": {"BatchSize": 1}},
        Target=tgt_arn,
        TargetParameters={"InputTemplate": _TEMPLATE},
        DesiredState="RUNNING",
        Tags=_RES_TAGS,
    )
    _wait_state(ctx, name, {"RUNNING"})

    order_id = uuid.uuid4().hex
    body = {"present": order_id}
    sent = sqs.send_message(QueueUrl=src_url, MessageBody=json.dumps(body))

    msg = _receive_until(ctx, tgt_url, order_id)
    rendered = json.loads(msg["Body"])

    assert "unresolved" in rendered, (
        f"a path that does not resolve must keep its key in the rendered template: {rendered!r}"
    )
    assert rendered["unresolved"] == "", (
        f"<$.body.missing>, which does not resolve, must render as an empty string, got "
        f"{rendered['unresolved']!r} in {rendered!r}"
    )

    whole_event = rendered["whole_event"]
    assert isinstance(whole_event, dict), (
        f"<aws.pipes.event.json> must render the whole source record as a JSON object, got "
        f"{whole_event!r}"
    )
    assert whole_event.get("messageId") == sent["MessageId"], (
        f"<aws.pipes.event.json> must carry the source record's own messageId "
        f"{sent['MessageId']!r}, got {whole_event.get('messageId')!r}"
    )
    assert whole_event.get("eventSourceARN") == src_arn, (
        f"<aws.pipes.event.json> must carry the source record's eventSourceARN {src_arn!r}, got "
        f"{whole_event.get('eventSourceARN')!r}"
    )
    # A JSON message body renders as the parsed object inside the whole event.
    raw_body = whole_event.get("body")
    assert raw_body == body, (
        f"<aws.pipes.event.json> must carry the source record's own body {body!r} unchanged, "
        f"got {raw_body!r}"
    )

    _delete_pipe_and_wait(ctx, name)


# ===== helpers (self-contained) =====


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


def _create_pipe_role(ctx, source_arns: list[str], target_arns: list[str]) -> str:
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
    statements = [
        {
            "Effect": "Allow",
            "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
            "Resource": source_arns,
        },
        {"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": target_arns},
    ]
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="pipe-access",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="pipe-access"))
    return role_arn


def _budget_s(ctx, cap_s):
    """A wait's timeout, bounded by the runner's remaining time so the wait fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


def _create_pipe_with_retry(ctx, timeout_s: float = 90.0, **kwargs) -> dict:
    """CreatePipe, retrying only while the fresh execution role is not yet assumable by Pipes."""
    pipes = ctx.client("pipes")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            resp = pipes.create_pipe(**kwargs)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"].get("Message", "")
            role_not_ready = code == "AccessDeniedException" or (
                code == "ValidationException"
                and ("cannot be assumed" in msg or "iam:PassRole" in msg)
            )
            if not role_not_ready:
                raise
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"CreatePipe was refused for its execution role for {timeout_s:.0f}s: {exc}"
                ) from exc
            time.sleep(2)
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
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            pipes.describe_pipe(Name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        time.sleep(3)
    raise TimeoutError(f"pipe {name} was still present {timeout_s:.0f}s after DeletePipe")


def _wait_state(ctx, name: str, states: set[str], timeout_s: float = 180.0) -> dict:
    pipes = ctx.client("pipes")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        desc = pipes.describe_pipe(Name=name)
        last = desc["CurrentState"]
        if last in states:
            return desc
        time.sleep(3)
    raise TimeoutError(f"pipe {name} never reached {sorted(states)}; last CurrentState was {last!r}")


def _receive_until(ctx, url: str, marker: str, timeout_s: float = 120.0) -> dict:
    """Poll `url` until a message whose body carries `marker` arrives; return it."""
    sqs = ctx.client("sqs")
    timeout_s = _budget_s(ctx, timeout_s)
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
    raise TimeoutError(f"no message carrying {marker!r} reached the queue within {timeout_s:.0f}s; saw {seen!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
