"""e2e-pipe-delivers-message-source-to-target."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-pipe-delivers-message-source-to-target"
GROUP = "e2e"
SERVICES = ["pipes"]

_TAGS = {"sim2real:managed": "true", "sim2real:check": CHECK}


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A started SQS-to-SQS pipe delivers an enqueued message byte-identical to the target and
    removes it from the source; the pipe can then be stopped and deleted cleanly."""
    sqs = ctx.client("sqs")
    pipes = ctx.client("pipes")

    src_url, src_arn = _create_sqs_queue(ctx)
    tgt_url, tgt_arn = _create_sqs_queue(ctx)

    role_arn = _create_pipe_role(ctx, [
        {"Effect": "Allow", "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"], "Resource": src_arn},
        {"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": tgt_arn},
    ])

    name = ctx.unique_name("sim2real-pipes-e2e-")
    _create_pipe_with_retry(
        ctx, pipes,
        Name=name,
        RoleArn=role_arn,
        Source=src_arn,
        SourceParameters={"SqsQueueParameters": {"BatchSize": 1}},
        Target=tgt_arn,
        DesiredState="STOPPED",
        Tags=_TAGS,
    )
    pipe_deleted = {"done": False}
    ctx.on_cleanup(lambda: None if pipe_deleted["done"] else _safe_cleanup(lambda: pipes.delete_pipe(Name=name)))
    _wait_pipe_current_state(ctx, pipes, name, {"STOPPED"})

    content = f"e2e-payload-{uuid.uuid4().hex[:12]}"
    sqs.send_message(QueueUrl=src_url, MessageBody=content)

    pipes.start_pipe(Name=name)
    _wait_pipe_current_state(ctx, pipes, name, {"RUNNING"})

    delivered = _wait_for_target_message(ctx, tgt_url, content, timeout_s=90)
    assert delivered == content, f"expected target body {content!r}, got {delivered!r}"

    # The source no longer holds the message: it was consumed and deleted, not just hidden.
    # ApproximateNumberOfMessages* is itself eventually consistent (AWS documents a lag of
    # up to a minute), so settle on a bounded retry rather than a single read.
    visible, in_flight = _wait_source_drained(ctx, src_url, timeout_s=90)
    assert visible == 0, f"expected 0 visible messages on drained source queue, got {visible}"
    assert in_flight == 0, f"expected 0 in-flight messages on drained source queue, got {in_flight}"

    pipes.stop_pipe(Name=name)
    _wait_pipe_current_state(ctx, pipes, name, {"STOPPED"})

    pipes.delete_pipe(Name=name)
    pipe_deleted["done"] = True
    deadline = time.monotonic() + 60
    gone = False
    while time.monotonic() < deadline:
        try:
            pipes.describe_pipe(Name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "NotFoundException":
                raise
            gone = True
            break
        time.sleep(3)
    assert gone, "pipe was not fully deleted within the timeout"

    # Not just gone from reads: a mutation against the dead id fails too.
    start_code, start_message = _client_error(lambda: pipes.start_pipe(Name=name), "StartPipe on the deleted pipe")
    assert start_code == "NotFoundException", f"expected NotFoundException starting deleted pipe, got {start_code!r}"
    expected_message = f"Pipe {name} does not exist."
    assert start_message == expected_message, (
        f"StartPipe on the deleted pipe: expected message {expected_message!r}, got {start_message!r}"
    )

    sqs.delete_queue(QueueUrl=src_url)
    sqs.delete_queue(QueueUrl=tgt_url)


def _client_error(fn, what):
    """Run a call that must be refused; return its (code, message). An accepted call raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"{what} must be refused, but it succeeded: {result!r}")


def _safe_cleanup(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "AWS.SimpleQueueService.NonExistentQueue",
            "NoSuchEntity",
            "NotFoundException",
            "QueueDoesNotExist",
        ):
            raise


def _create_sqs_queue(ctx, *, fifo=False, extra_attrs=None):
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-pipes-q-")
    attrs = {}
    if fifo:
        name = f"{name}.fifo"
        attrs["FifoQueue"] = "true"
        attrs["ContentBasedDeduplication"] = "true"
    if extra_attrs:
        attrs.update(extra_attrs)
    kwargs = {"QueueName": name, "tags": _TAGS}
    if attrs:
        kwargs["Attributes"] = attrs
    url = sqs.create_queue(**kwargs)["QueueUrl"]
    ctx.on_cleanup(lambda: _safe_cleanup(lambda: sqs.delete_queue(QueueUrl=url)))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_pipe_role(ctx, statements):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-pipes-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "pipes.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe_cleanup(lambda: iam.delete_role(RoleName=role_name)))
    policy_name = ctx.unique_name("sim2real-pipes-pol-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: _safe_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)))
    return role_arn


def _create_pipe_with_retry(ctx, pipes, *, timeout_s=90, **kwargs):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return pipes.create_pipe(**kwargs)
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                last_err = e
                time.sleep(3)
                continue
            raise
    raise last_err


def _wait_pipe_current_state(ctx, pipes, name, states, timeout_s=150, interval_s=3):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = pipes.describe_pipe(Name=name)["CurrentState"]
        if last in states:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"pipe {name} never reached {states}, last state was {last}")


def _wait_source_drained(ctx, src_url, timeout_s=90, interval_s=3):
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    visible, in_flight = None, None
    while time.monotonic() < deadline:
        attrs = sqs.get_queue_attributes(
            QueueUrl=src_url,
            AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
        )["Attributes"]
        visible = int(attrs["ApproximateNumberOfMessages"])
        in_flight = int(attrs["ApproximateNumberOfMessagesNotVisible"])
        if visible == 0 and in_flight == 0:
            return visible, in_flight
        time.sleep(interval_s)
    return visible, in_flight


def _wait_for_target_message(ctx, tgt_url, expected_body, timeout_s=90):
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=tgt_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            payload = json.loads(msg["Body"])
            record = payload[0] if isinstance(payload, list) else payload
            sqs.delete_message(QueueUrl=tgt_url, ReceiptHandle=msg["ReceiptHandle"])
            if record.get("body") == expected_body:
                return record["body"]
    raise AssertionError(f"target never received a message with body {expected_body!r} within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
