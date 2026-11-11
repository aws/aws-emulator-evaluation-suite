"""sqs-source-batch-window-delays-processing."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sqs-source-batch-window-delays-processing"
GROUP = "visibility-timeout-ttl"
SERVICES = ["pipes"]

BATCH_WINDOW_SECONDS = 20
_RES_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-pipes-bw"}


# timing:real-time — buffer: 20 s https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-batching-concurrency.html
@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A pipe configured with MaximumBatchingWindowInSeconds on its SQS source delays
    invoking the target until the window elapses, rather than forwarding a single
    low-traffic message immediately."""
    sqs = ctx.client("sqs")
    pipes = ctx.client("pipes")

    src_url, src_arn = _create_sqs_queue(ctx)
    tgt_url, tgt_arn = _create_sqs_queue(ctx)

    role_arn = _create_pipe_role(ctx, [
        {"Effect": "Allow", "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"], "Resource": src_arn},
        {"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": tgt_arn},
    ])

    name = ctx.unique_name("sim2real-pipes-bw-")
    _create_pipe_with_retry(
        ctx, pipes,
        Name=name,
        RoleArn=role_arn,
        Source=src_arn,
        SourceParameters={
            "SqsQueueParameters": {"BatchSize": 10, "MaximumBatchingWindowInSeconds": BATCH_WINDOW_SECONDS}
        },
        Target=tgt_arn,
        TargetParameters={
            # Without an InputTemplate, Pipes forwards the whole source-event envelope
            # (messageId/receiptHandle/attributes/etc) as the target message body, not the
            # raw SQS body. Extract just the original body so the terminal read can compare
            # against the exact payload sent.
            "InputTemplate": "<$.body>",
        },
        DesiredState="STOPPED",
        Tags=_RES_TAGS,
    )
    ctx.on_cleanup(lambda: _safe_cleanup(lambda: pipes.delete_pipe(Name=name)))
    _wait_pipe_current_state(ctx, pipes, name, {"STOPPED"})

    pipes.start_pipe(Name=name)
    _wait_pipe_current_state(ctx, pipes, name, {"RUNNING"})

    t_send = time.monotonic()
    sqs.send_message(QueueUrl=src_url, MessageBody="batch-window-probe")

    # Well before the configured window elapses, the single low-traffic message must NOT
    # have reached the target yet (batch size of 10 is never reached with 1 message).
    early_deadline = time.monotonic() + min(8.0, BATCH_WINDOW_SECONDS * 0.4)
    while time.monotonic() < early_deadline:
        attrs = sqs.get_queue_attributes(
            QueueUrl=tgt_url, AttributeNames=["ApproximateNumberOfMessages"]
        )["Attributes"]
        assert int(attrs["ApproximateNumberOfMessages"]) == 0, (
            "target received the message before the batching window elapsed"
        )
        time.sleep(2)

    t_arrive = None
    received_body = None
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=tgt_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
        msgs = resp.get("Messages", [])
        if msgs:
            t_arrive = time.monotonic()
            received_body = msgs[0]["Body"]
            sqs.delete_message(QueueUrl=tgt_url, ReceiptHandle=msgs[0]["ReceiptHandle"])
            break
        time.sleep(2)
    assert t_arrive is not None, "message never arrived at the target"
    assert received_body == "batch-window-probe", (
        f"target received unexpected body {received_body!r}, expected 'batch-window-probe'"
    )

    elapsed = t_arrive - t_send
    assert elapsed >= BATCH_WINDOW_SECONDS * 0.5, (
        f"message arrived after only {elapsed:.1f}s, well under the configured "
        f"MaximumBatchingWindowInSeconds={BATCH_WINDOW_SECONDS}"
    )


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
        Tags=[{"Key": k, "Value": v} for k, v in _RES_TAGS.items()],
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
