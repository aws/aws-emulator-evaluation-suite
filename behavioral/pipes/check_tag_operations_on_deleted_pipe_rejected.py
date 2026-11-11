"""tag-operations-on-deleted-pipe-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-operations-on-deleted-pipe-rejected"
GROUP = "error-semantics"
SERVICES = ["pipes"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource/UntagResource/ListTagsForResource against a deleted pipe ARN each return NotFoundException."""
    pipes = ctx.client("pipes")
    role_arn = _create_pipes_role(ctx)
    source_url, source_arn = _create_queue(ctx, "src")
    target_url, target_arn = _create_queue(ctx, "tgt")
    _grant_pipe_permissions(ctx, role_arn, source_arn, target_arn)

    name = ctx.unique_name("sim2real-pipes-tagdel-")
    create_resp = _create_pipe_with_retry(
        ctx,
        pipes,
        Name=name,
        Source=source_arn,
        Target=target_arn,
        RoleArn=role_arn,
        DesiredState="STOPPED",
        Tags={"env": "sim2real"},
    )
    pipe_arn = create_resp["Arn"]

    _poll_until(
        lambda: pipes.describe_pipe(Name=name),
        lambda d: d["CurrentState"] in ("STOPPED", "CREATE_FAILED"),
        timeout_s=180.0,
    )

    # Positive control: tag operations succeed while the pipe is alive.
    tags_before = pipes.list_tags_for_resource(resourceArn=pipe_arn)["tags"]
    assert tags_before.get("env") == "sim2real", "positive control: tags must be readable on a live pipe"

    # Delete the pipe fully.
    pipes.delete_pipe(Name=name)

    def _describe_or_gone():
        try:
            return pipes.describe_pipe(Name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                return "GONE"
            raise

    _poll_until(_describe_or_gone, lambda v: v == "GONE", timeout_s=180.0)

    # Break exactly one thing under test: tag operations against a now-deleted pipe ARN.
    tag_code, tag_message = _error(lambda: pipes.tag_resource(resourceArn=pipe_arn, tags={"env": "after-delete"}))
    assert tag_code == "NotFoundException", f"expected NotFoundException from TagResource, got {tag_code!r}"
    assert tag_message == "Resource was not found", f"unexpected TagResource message {tag_message!r}"

    untag_code, untag_message = _error(lambda: pipes.untag_resource(resourceArn=pipe_arn, tagKeys=["env"]))
    assert untag_code == "NotFoundException", f"expected NotFoundException from UntagResource, got {untag_code!r}"
    assert untag_message == "Resource was not found", f"unexpected UntagResource message {untag_message!r}"

    list_code, list_message = _error(lambda: pipes.list_tags_for_resource(resourceArn=pipe_arn))
    assert list_code == "NotFoundException", f"expected NotFoundException from ListTagsForResource, got {list_code!r}"
    assert list_message == "Resource was not found", f"unexpected ListTagsForResource message {list_message!r}"


# ===== helpers =====

def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    SUCCESS raises, so a target accepting what real AWS refuses fails loudly instead of
    reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _create_queue(ctx, suffix: str) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name(f"sim2real-pipes-{suffix}-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_pipes_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-pipes-role-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "pipes.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)["Role"]["Arn"]

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="inline")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _grant_pipe_permissions(ctx, role_arn: str, source_arn: str, target_arn: str) -> None:
    iam = ctx.client("iam")
    role_name = role_arn.split("/")[-1]
    policy = {
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
    iam.put_role_policy(RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(policy))


def _create_pipe_with_retry(ctx, pipes, **kwargs: Any):
    """CreatePipe, retrying for up to 60 s while the fresh execution role is still propagating."""
    left = ctx.time_left()
    deadline = time.monotonic() + (60.0 if left is None else max(1.0, min(60.0, left - 10.0)))
    while True:
        try:
            return pipes.create_pipe(**kwargs)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("ValidationException", "NotFoundException") and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
