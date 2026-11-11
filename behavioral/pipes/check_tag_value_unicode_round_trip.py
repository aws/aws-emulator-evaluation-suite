"""tag-value-unicode-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-value-unicode-round-trip"
GROUP = "representation"
SERVICES = ["pipes"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A tag value containing multi-byte unicode characters and emoji, written via
    TagResource, is returned byte-identical via ListTagsForResource."""
    pipes = ctx.client("pipes")

    src_url, src_arn = _create_sqs_queue(ctx)
    tgt_url, tgt_arn = _create_sqs_queue(ctx)
    role_arn = _create_pipe_role(ctx, [{"Effect": "Allow", "Action": "sqs:*", "Resource": [src_arn, tgt_arn]}])

    name = ctx.unique_name("sim2real-pipes-tagu-")
    resp = _create_pipe_with_retry(
        ctx, pipes,
        Name=name,
        RoleArn=role_arn,
        Source=src_arn,
        SourceParameters={"SqsQueueParameters": {"BatchSize": 1}},
        Target=tgt_arn,
        DesiredState="STOPPED",
    )
    arn = resp["Arn"]
    ctx.on_cleanup(lambda: _safe_cleanup(lambda: pipes.delete_pipe(Name=name)))

    # Pipes tags accept unicode letters/numbers/spaces plus a fixed set of ASCII
    # punctuation (+ - = . _ : / @) -- symbol/emoji code points outside \p{L}/\p{N} are
    # rejected by validation, so the round-trip probe sticks to multi-byte *letters*
    # (CJK ideographs, accented Latin) combined with only the allowed punctuation.
    unicode_value = "\u65e5\u672c\u8a9e-caf\u00e9-\u00dcber_test.value:2024/01+ok=yes"
    pipes.tag_resource(resourceArn=arn, tags={"unicode-tag": unicode_value})

    tags = pipes.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags["unicode-tag"] == unicode_value

    # Positive control on the documented boundary: a value containing an emoji (outside
    # \p{L}/\p{N} and the allowed punctuation set) is rejected, not silently mangled.
    emoji_code, emoji_message = _error(lambda: pipes.tag_resource(resourceArn=arn, tags={"emoji-tag": "\U0001F680"}))
    assert emoji_code == "BadRequestException", (
        f"expected BadRequestException for an emoji tag value, got {emoji_code!r}"
    )
    assert emoji_message == (
        "Tags can only contain letters, numbers, spaces, and the following special characters: _ . : / = + - @"
    ), f"unexpected TagResource message {emoji_message!r}"

    # Effect absent: the rejected emoji tag never landed, and the earlier unicode tag
    # is unaffected by the failed call.
    tags_after = pipes.list_tags_for_resource(resourceArn=arn)["tags"]
    assert "emoji-tag" not in tags_after, f"emoji-tag should not exist, found {tags_after!r}"
    assert tags_after["unicode-tag"] == unicode_value


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    SUCCESS raises, so a target accepting what real AWS refuses fails loudly instead of
    reading as a code mismatch."""
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
    kwargs = {"QueueName": name, "tags": {"sim2real:managed": "true"}}
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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
