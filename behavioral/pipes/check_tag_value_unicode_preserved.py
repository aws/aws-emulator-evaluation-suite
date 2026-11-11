"""tag-value-unicode-preserved."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "tag-value-unicode-preserved"
GROUP = "representation"
SERVICES = ["pipes"]

_TAG_VALUE = "\u65e5\u672c\u8a9e \u0440\u0443\u0441\u0441\u043a\u0438\u0439 caf\u00e9"

_TRANSITIONAL = {"CREATING", "UPDATING", "DELETING", "STARTING", "STOPPING"}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A tag value containing unicode text survives TagResource -> ListTagsForResource unchanged."""
    source_url, source_arn = _create_queue(ctx, "sim2real-pipes-src-")
    _, target_arn = _create_queue(ctx, "sim2real-pipes-tgt-")
    role_arn = _create_pipe_role(ctx, source_arn, target_arn)

    pipes = ctx.client("pipes")
    name = ctx.unique_name("sim2real-pipes-tag-")
    created = pipes.create_pipe(
        Name=name,
        Source=source_arn,
        Target=target_arn,
        RoleArn=role_arn,
        DesiredState="STOPPED",
    )
    ctx.on_cleanup(lambda: pipes.delete_pipe(Name=name))
    _wait_pipe_stable(ctx, name)
    pipe_arn = created["Arn"]

    pipes.tag_resource(resourceArn=pipe_arn, tags={"unicode-tag": _TAG_VALUE})
    tags = pipes.list_tags_for_resource(resourceArn=pipe_arn)["tags"]
    assert tags.get("unicode-tag") == _TAG_VALUE, (
        f"tag value not preserved: {tags.get('unicode-tag')!r} != {_TAG_VALUE!r}"
    )


def _create_queue(ctx, prefix):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name(prefix))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_pipe_role(ctx, source_arn, target_arn):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-pipes-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "pipes.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    role_arn = role["Role"]["Arn"]
    policy_name = "pipe-access"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
                "Resource": source_arn,
            },
            {"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": target_arn},
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _wait_pipe_stable(ctx, name, timeout_s=90.0, interval_s=3.0):
    pipes = ctx.client("pipes")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = pipes.describe_pipe(Name=name)
        if last["CurrentState"] not in _TRANSITIONAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"pipe {name} did not stabilize within {timeout_s}s "
        f"(last state {last['CurrentState'] if last else None})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
