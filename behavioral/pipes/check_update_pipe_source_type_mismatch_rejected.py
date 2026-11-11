"""update-pipe-source-type-mismatch-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-pipe-source-type-mismatch-rejected"
GROUP = "server-side"
SERVICES = ["pipes"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdatePipe rejects DynamoDBStreamParameters for an SQS-sourced pipe (Source is immutable),
    leaving its SQS source parameters untouched; a valid SQS SourceParameters update succeeds."""
    pipes = ctx.client("pipes")
    res_tags = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-pipes-mismatch"}

    src_url, src_arn = _create_sqs_queue(ctx, res_tags)
    tgt_url, tgt_arn = _create_sqs_queue(ctx, res_tags)
    role_arn = _create_pipe_role(
        ctx, [{"Effect": "Allow", "Action": "sqs:*", "Resource": [src_arn, tgt_arn]}], res_tags
    )

    name = ctx.unique_name("sim2real-pipes-mismatch-")
    _create_pipe_with_retry(
        ctx, pipes,
        Name=name,
        RoleArn=role_arn,
        Source=src_arn,
        SourceParameters={"SqsQueueParameters": {"BatchSize": 3}},
        Target=tgt_arn,
        DesiredState="STOPPED",
        Tags=res_tags,
    )
    ctx.on_cleanup(lambda: _safe_cleanup(lambda: pipes.delete_pipe(Name=name)))
    _wait_pipe_current_state(ctx, pipes, name, {"STOPPED"})

    code, message = _error(lambda: pipes.update_pipe(
        Name=name,
        RoleArn=role_arn,
        SourceParameters={"DynamoDBStreamParameters": {"BatchSize": 5}},
    ))
    assert code == "ValidationException", f"expected ValidationException for a source-type mismatch, got {code}"
    assert message == (
        '{"ValidationErrorFields":[{"Name":"DynamoDBStreamParameters","Message":"Invalid source parameter provided for source sqs."}]}'
    ), f"unexpected UpdatePipe message {message!r}"

    # Effect absent: the pipe's real SQS source parameters are unchanged, and the
    # incompatible DynamoDB parameters were never applied.
    unchanged = pipes.describe_pipe(Name=name)
    assert unchanged["SourceParameters"]["SqsQueueParameters"]["BatchSize"] == 3, (
        f"expected the SQS BatchSize to remain 3 after the rejected update, "
        f"got {unchanged['SourceParameters'].get('SqsQueueParameters')}"
    )
    assert "DynamoDBStreamParameters" not in unchanged["SourceParameters"], (
        f"DynamoDBStreamParameters must never have been applied, got keys "
        f"{list(unchanged['SourceParameters'])}"
    )
    assert unchanged["CurrentState"] == "STOPPED", (
        f"a rejected UpdatePipe must not move CurrentState, expected STOPPED got {unchanged['CurrentState']}"
    )

    # Positive control: a valid SQS SourceParameters update on the same pipe succeeds.
    pipes.update_pipe(
        Name=name,
        RoleArn=role_arn,
        SourceParameters={"SqsQueueParameters": {"BatchSize": 7}},
    )
    _wait_pipe_current_state(ctx, pipes, name, {"STOPPED"})
    updated = pipes.describe_pipe(Name=name)
    assert updated["SourceParameters"]["SqsQueueParameters"]["BatchSize"] == 7, (
        f"expected the same-type positive control to raise BatchSize to 7, "
        f"got {updated['SourceParameters'].get('SqsQueueParameters')}"
    )


def _error(fn):
    """Return the (code, message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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


def _create_sqs_queue(ctx, res_tags, *, fifo=False, extra_attrs=None):
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-pipes-q-")
    attrs = {}
    if fifo:
        name = f"{name}.fifo"
        attrs["FifoQueue"] = "true"
        attrs["ContentBasedDeduplication"] = "true"
    if extra_attrs:
        attrs.update(extra_attrs)
    kwargs = {"QueueName": name, "tags": res_tags}
    if attrs:
        kwargs["Attributes"] = attrs
    url = sqs.create_queue(**kwargs)["QueueUrl"]
    ctx.on_cleanup(lambda: _safe_cleanup(lambda: sqs.delete_queue(QueueUrl=url)))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_pipe_role(ctx, statements, res_tags):
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
    tags = [{"Key": k, "Value": v} for k, v in res_tags.items()]
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
