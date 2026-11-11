"""update-pipe-wrong-source-type-parameters-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-pipe-wrong-source-type-parameters-rejected"
GROUP = "overly-permissive"
SERVICES = ["pipes"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdatePipe rejects SourceParameters for a stream type that doesn't match the pipe's
    existing (immutable) SQS source, leaves the prior configuration untouched, and a
    same-type update in the same file still succeeds."""
    source = _create_queue(ctx, "src")
    target = _create_queue(ctx, "tgt")
    role_arn = _create_pipe_role(
        ctx,
        [
            {
                "Effect": "Allow",
                "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
                "Resource": source["arn"],
            },
            {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": target["arn"]},
        ],
    )

    pipes = ctx.client("pipes")
    name = ctx.unique_name("sim2real-pipes-wrongsrc-")
    _create_pipe_with_retry(
        ctx,
        Name=name,
        DesiredState="STOPPED",
        Source=source["arn"],
        Target=target["arn"],
        RoleArn=role_arn,
        SourceParameters={"SqsQueueParameters": {"BatchSize": 3}},
        Tags={t["Key"]: t["Value"] for t in _TAGS},
    )
    ctx.on_cleanup(lambda: pipes.delete_pipe(Name=name))
    _wait_for_pipe_state(ctx, name, {"STOPPED"}, timeout_s=60)

    code, message = _error(
        lambda: pipes.update_pipe(
            Name=name,
            RoleArn=role_arn,
            SourceParameters={"KinesisStreamParameters": {"BatchSize": 5}},
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException when SourceParameters don't match the SQS source type, got {code}"
    )
    assert message == (
        '{"ValidationErrorFields":[{"Name":"KinesisStreamParameters","Message":"Invalid source parameter provided for source sqs."}]}'
    ), f"unexpected UpdatePipe message {message!r}"

    # Effect absent: the existing SQS source configuration must be untouched.
    desc = pipes.describe_pipe(Name=name)
    assert desc["SourceParameters"]["SqsQueueParameters"]["BatchSize"] == 3, (
        f"rejected update must leave BatchSize at 3, got {desc['SourceParameters']['SqsQueueParameters']['BatchSize']}"
    )
    assert "KinesisStreamParameters" not in desc["SourceParameters"], (
        f"rejected KinesisStreamParameters must never be applied, got {desc['SourceParameters']}"
    )
    assert desc["CurrentState"] == "STOPPED", f"expected CurrentState STOPPED, got {desc['CurrentState']}"

    # Positive control: a same-type SourceParameters update still succeeds.
    pipes.update_pipe(
        Name=name,
        RoleArn=role_arn,
        SourceParameters={"SqsQueueParameters": {"BatchSize": 7}},
    )
    final = _wait_for_pipe_state(ctx, name, {"STOPPED"}, timeout_s=60)
    assert final["SourceParameters"]["SqsQueueParameters"]["BatchSize"] == 7, (
        f"expected same-type update to apply BatchSize 7, got {final['SourceParameters']['SqsQueueParameters']['BatchSize']}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    SUCCESS raises, so a target accepting what real AWS refuses fails loudly instead of
    reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


_TAGS = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-pipes"}]


def _create_pipe_role(ctx, statements: list[dict]) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-pipes-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "pipes.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_TAGS
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_doc = {"Version": "2012-10-17", "Statement": statements}
    iam.put_role_policy(RoleName=role_name, PolicyName="pipes-access", PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="pipes-access"))
    return role_arn


def _create_queue(ctx, name_hint: str, fifo: bool = False, attributes: dict | None = None) -> dict:
    sqs = ctx.client("sqs")
    name = ctx.unique_name(f"sim2real-pipes-{name_hint}-")
    if fifo:
        name += ".fifo"
    attrs = dict(attributes or {})
    if fifo:
        attrs["FifoQueue"] = "true"
    url = sqs.create_queue(
        QueueName=name, Attributes=attrs, tags={t["Key"]: t["Value"] for t in _TAGS}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


def _create_pipe_with_retry(ctx, **kwargs):
    """CreatePipe can transiently reject a just-created RoleArn (IAM eventual consistency)."""
    pipes = ctx.client("pipes")
    last_err = None
    for _ in range(15):
        try:
            return pipes.create_pipe(**kwargs)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("ValidationException", "NotFoundException", "AccessDeniedException"):
                last_err = e
                time.sleep(3)
                continue
            raise
    raise last_err


def _wait_for_pipe_state(ctx, name: str, target_states: set, timeout_s: float = 90.0, interval_s: float = 2.0):
    pipes = ctx.client("pipes")
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = pipes.describe_pipe(Name=name)
        if desc["CurrentState"] in target_states:
            return desc
        time.sleep(interval_s)
    last = desc["CurrentState"] if desc else None
    raise AssertionError(f"pipe {name} did not reach {target_states}, last state={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
