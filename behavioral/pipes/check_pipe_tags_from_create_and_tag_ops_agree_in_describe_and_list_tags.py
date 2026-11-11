"""pipe-tags-from-create-and-tag-ops-agree-in-describe-and-list-tags."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pipe-tags-from-create-and-tag-ops-agree-in-describe-and-list-tags"
GROUP = "tagging"
SERVICES = ["pipes"]

_RES_TAGS = {"sim2real": CHECK}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags given to CreatePipe, then changed by TagResource and UntagResource, read back the
    same through DescribePipe.Tags and ListTagsForResource at every step."""
    pipes = ctx.client("pipes")
    _, src_arn = _create_queue(ctx, "sim2real-pipes-tagrt-src-")
    _, tgt_arn = _create_queue(ctx, "sim2real-pipes-tagrt-dst-")
    role_arn = _create_pipe_role(ctx, _sqs_pipe_statements([src_arn], [tgt_arn]))

    name = ctx.unique_name("sim2real-pipes-tagrt-")
    initial = {**_RES_TAGS, "team": "payments", "tier": "gold"}
    created = _create_pipe_with_retry(
        ctx, Name=name, RoleArn=role_arn, Source=src_arn, Target=tgt_arn, DesiredState="STOPPED", Tags=initial
    )
    arn = created["Arn"]
    _wait_state(ctx, name, {"STOPPED"})

    def both() -> tuple[dict, dict]:
        return pipes.describe_pipe(Name=name).get("Tags", {}), pipes.list_tags_for_resource(resourceArn=arn)["tags"]

    described, listed = both()
    assert described == initial, f"DescribePipe.Tags after create: {described!r}, expected {initial!r}"
    assert listed == initial, f"ListTagsForResource after create: {listed!r}, expected {initial!r}"

    pipes.tag_resource(resourceArn=arn, tags={"tier": "platinum", "owner": "ops"})
    after_tag = {**initial, "tier": "platinum", "owner": "ops"}
    described, listed = both()
    assert described == after_tag, f"DescribePipe.Tags after TagResource: {described!r}, expected {after_tag!r}"
    assert listed == after_tag, f"ListTagsForResource after TagResource: {listed!r}, expected {after_tag!r}"

    pipes.untag_resource(resourceArn=arn, tagKeys=["team", "owner"])
    after_untag = {**_RES_TAGS, "tier": "platinum"}
    described, listed = both()
    assert described == after_untag, f"DescribePipe.Tags after UntagResource: {described!r}, expected {after_untag!r}"
    assert listed == after_untag, f"ListTagsForResource after UntagResource: {listed!r}, expected {after_untag!r}"

    _delete_pipe_and_wait(ctx, name)


# ===== helpers =====


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
