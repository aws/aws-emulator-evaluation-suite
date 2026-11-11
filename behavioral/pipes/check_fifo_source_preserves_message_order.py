"""fifo-source-preserves-message-order."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "fifo-source-preserves-message-order"
GROUP = "ordering"
SERVICES = ["pipes"]

_RES_TAGS = {"sim2real:managed": "true", "sim2real:check": CHECK}
_IAM_TAGS = [{"Key": k, "Value": v} for k, v in _RES_TAGS.items()]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """Messages enqueued to the same message group on a FIFO SQS source are delivered to
    the target queue in the exact order they were sent."""
    sqs = ctx.client("sqs")
    pipes = ctx.client("pipes")

    src_url, src_arn = _create_sqs_queue(ctx, fifo=True)
    tgt_url, tgt_arn = _create_sqs_queue(ctx, fifo=True)

    role_arn = _create_pipe_role(ctx, [
        {"Effect": "Allow", "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"], "Resource": src_arn},
        {"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": tgt_arn},
    ])

    name = ctx.unique_name("sim2real-pipes-fifo-")
    group_id = "order-test-group"
    _create_pipe_with_retry(
        ctx, pipes,
        Name=name,
        RoleArn=role_arn,
        Source=src_arn,
        SourceParameters={"SqsQueueParameters": {"BatchSize": 1}},
        Target=tgt_arn,
        TargetParameters={"SqsQueueParameters": {"MessageGroupId": group_id}},
        DesiredState="STOPPED",
        Tags=_RES_TAGS,
    )
    ctx.on_cleanup(lambda: _safe_cleanup(lambda: pipes.delete_pipe(Name=name)))
    _wait_pipe_current_state(ctx, pipes, name, {"STOPPED"})

    bodies = ["order-1", "order-2", "order-3"]
    for i, body in enumerate(bodies):
        sqs.send_message(
            QueueUrl=src_url,
            MessageBody=body,
            MessageGroupId=group_id,
            MessageDeduplicationId=f"{name}-{i}",
        )

    pipes.start_pipe(Name=name)
    _wait_pipe_current_state(ctx, pipes, name, {"RUNNING"})

    received = []
    deadline = time.monotonic() + 120
    while len(received) < len(bodies) and time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=tgt_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            payload = json.loads(msg["Body"])
            record = payload[0] if isinstance(payload, list) else payload
            received.append(record["body"])
            sqs.delete_message(QueueUrl=tgt_url, ReceiptHandle=msg["ReceiptHandle"])

    assert received == bodies, f"expected order {bodies}, got {received}"


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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_IAM_TAGS
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
