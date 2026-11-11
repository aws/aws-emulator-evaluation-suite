"""sqs-source-visibility-timeout-enforced."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sqs-source-visibility-timeout-enforced"
GROUP = "visibility-timeout-ttl"
SERVICES = ["pipes"]

VISIBILITY_TIMEOUT = 10
_RES_TAGS = {"sim2real:managed": "true", "sim2real:check": CHECK}


# timing:real-time — visibility: 10 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html
@tags("axis:negative-delivery", "cap:c2", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """While a pipe holds an SQS message in flight, an independent receive gets nothing; when the
    target rejects delivery the message is not dropped and returns with ReceiveCount > 1."""
    sqs = ctx.client("sqs")
    pipes = ctx.client("pipes")

    src_url, src_arn = _create_sqs_queue(ctx, extra_attrs={"VisibilityTimeout": str(VISIBILITY_TIMEOUT)})
    # Target queue: the pipe's role is deliberately NOT granted permission on it, so every
    # delivery attempt fails and the source message is never deleted.
    tgt_url, tgt_arn = _create_sqs_queue(ctx)

    role_arn = _create_pipe_role(ctx, [
        {
            "Effect": "Allow",
            "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
            "Resource": src_arn,
        },
    ])

    name = ctx.unique_name("sim2real-pipes-vt-")
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

    sqs.send_message(QueueUrl=src_url, MessageBody="visibility-timeout-probe")
    pipes.start_pipe(Name=name)
    _wait_pipe_current_state(ctx, pipes, name, {"RUNNING"})

    def _attrs():
        return sqs.get_queue_attributes(
            QueueUrl=src_url,
            AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
        )["Attributes"]

    t_detect = None
    deadline = time.monotonic() + _budget_s(ctx, 120)
    while time.monotonic() < deadline:
        a = _attrs()
        if int(a["ApproximateNumberOfMessagesNotVisible"]) >= 1:
            t_detect = time.monotonic()
            break
        time.sleep(2)
    if t_detect is None and _budget_spent(ctx):
        raise TimeoutError("the pipe picking up the message: the run budget ended first; not graded")
    assert t_detect is not None, "pipe never picked up the message from the source queue"

    # An atomic SQS guarantee, not an approximate metric: within the VisibilityTimeout no
    # other ReceiveMessage can return a message checked out by the pipe.
    for _ in range(3):
        resp = sqs.receive_message(QueueUrl=src_url, MaxNumberOfMessages=10, WaitTimeSeconds=0)
        assert not resp.get("Messages"), (
            "a concurrent receive returned the message while it was still checked out by "
            "the pipe, inside its configured VisibilityTimeout"
        )

    # The pipe stops polling before the message is received here, so its own pollers cannot
    # take the message again the moment it turns visible. A receive that then shows
    # ApproximateReceiveCount > 1 proves the failed delivery left it in the queue and the
    # hide/release cycle ran at least once.
    pipes.stop_pipe(Name=name)
    _wait_pipe_current_state(ctx, pipes, name, {"STOPPED"})
    reprocessed = False
    receive_count_seen = None
    deadline2 = time.monotonic() + _budget_s(ctx, 90)
    while time.monotonic() < deadline2 and not reprocessed:
        resp = sqs.receive_message(
            QueueUrl=src_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=2,
            AttributeNames=["ApproximateReceiveCount"],
        )
        for msg in resp.get("Messages", []):
            receive_count_seen = int(msg["Attributes"]["ApproximateReceiveCount"])
            if receive_count_seen > 1:
                reprocessed = True
            # Release it again right away so the pipe can keep retrying too.
            sqs.change_message_visibility(QueueUrl=src_url, ReceiptHandle=msg["ReceiptHandle"], VisibilityTimeout=0)
    if not reprocessed and _budget_spent(ctx):
        raise TimeoutError("the message returning for reprocessing: the run budget ended first; not graded")
    assert reprocessed, (
        f"message was never observed with ApproximateReceiveCount > 1 within 90s "
        f"(last seen count: {receive_count_seen!r}) -- it was never actually reprocessed"
    )

    tgt_attrs = sqs.get_queue_attributes(
        QueueUrl=tgt_url, AttributeNames=["ApproximateNumberOfMessages"]
    )["Attributes"]
    assert int(tgt_attrs["ApproximateNumberOfMessages"]) == 0, (
        "message reached the target despite the pipe's role lacking permission to send there"
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
    tags = [{"Key": k, "Value": v} for k, v in _RES_TAGS.items()]
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=tags
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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_pipe_current_state(ctx, pipes, name, states, timeout_s=150, interval_s=2):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = pipes.describe_pipe(Name=name)["CurrentState"]
        if last in states:
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"pipe {name} reaching {states}: the run budget ended first; not graded")
    raise AssertionError(f"pipe {name} never reached {states}, last state was {last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
