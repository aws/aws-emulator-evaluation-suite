"""pipe-server-side-polling-without-client-action."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pipe-server-side-polling-without-client-action"
GROUP = "server-side"
SERVICES = ["pipes"]

_RES_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-pipes-bg"}
_RES_TAGS_KV = [{"Key": k, "Value": v} for k, v in _RES_TAGS.items()]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """Once StartPipe succeeds, EventBridge Pipes autonomously keeps polling the source and
    invoking the target -- no further Pipes API calls are needed to keep processing new
    messages that show up well after the start call and a quiet gap."""
    sqs = ctx.client("sqs")
    pipes = ctx.client("pipes")

    src_url, src_arn = _create_sqs_queue(ctx)
    tgt_url, tgt_arn = _create_sqs_queue(ctx)

    role_arn = _create_pipe_role(ctx, [
        {"Effect": "Allow", "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"], "Resource": src_arn},
        {"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": tgt_arn},
    ])

    name = ctx.unique_name("sim2real-pipes-bg-")
    _create_pipe_with_retry(
        ctx, pipes,
        Name=name,
        RoleArn=role_arn,
        Source=src_arn,
        SourceParameters={"SqsQueueParameters": {"BatchSize": 1}},
        Target=tgt_arn,
        DesiredState="STOPPED",
        Tags=_RES_TAGS,
    )
    ctx.on_cleanup(lambda: _safe_cleanup(lambda: pipes.delete_pipe(Name=name)))
    _wait_pipe_current_state(ctx, pipes, name, {"STOPPED"})

    pipes.start_pipe(Name=name)
    _wait_pipe_current_state(ctx, pipes, name, {"RUNNING"})

    # From this point on, no further Pipes API call is made -- only SQS reads/writes used
    # purely to observe the effect, and DescribePipe was already used solely to confirm the
    # pipe reached RUNNING before we stop touching the Pipes API entirely.
    sqs.send_message(QueueUrl=src_url, MessageBody="bg-probe-1")
    first = _wait_for_target_message(ctx, tgt_url, "bg-probe-1", timeout_s=90)
    assert first == "bg-probe-1", f"expected the first probe to arrive at the target, got {first!r}"

    # A deliberate quiet gap with zero Pipes API activity: hold it open with an active bounded
    # poll rather than a blind sleep, asserting the target sees nothing stray or duplicated while
    # idle, then a second, independent message proves the service is still autonomously polling
    # the source in the background.
    _assert_quiet(ctx, sqs, tgt_url, gap_s=15)
    sqs.send_message(QueueUrl=src_url, MessageBody="bg-probe-2")
    second = _wait_for_target_message(ctx, tgt_url, "bg-probe-2", timeout_s=90)
    assert second == "bg-probe-2", f"expected the second probe to arrive at the target, got {second!r}"


def _error_code(fn):
    try:
        fn()
        return None
    except ClientError as e:
        return e.response["Error"]["Code"]


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
    kwargs = {"QueueName": name, "tags": _RES_TAGS}
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
        Tags=_RES_TAGS_KV,
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


def _assert_quiet(ctx, sqs, tgt_url, gap_s):
    """Hold a quiet window open for at least ``gap_s`` seconds with zero Pipes API activity,
    asserting on every poll that the target sees nothing stray -- a bounded, actively-checked
    wait rather than a blind sleep."""
    deadline = time.monotonic() + gap_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=tgt_url, MaxNumberOfMessages=10, WaitTimeSeconds=3)
        stray = resp.get("Messages", [])
        assert not stray, f"target received unexpected message(s) during the quiet gap: {stray}"


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
