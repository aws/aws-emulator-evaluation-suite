"""topic-policy-round-trips-and-deleted-topic-set-attributes-not-found."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "topic-policy-round-trips-and-deleted-topic-set-attributes-not-found"
GROUP = "state-machine"
SERVICES = ["sns"]


def _error(fn):
    """The (code, message) ``fn`` raises; an unexpected success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A topic Policy set with SetTopicAttributes reads back exactly through GetTopicAttributes.

    Once the topic is deleted, Get and SetTopicAttributes on its ARN are refused with NotFound.
    """
    sns = ctx.client("sns")
    arn = sns.create_topic(Name=ctx.unique_name("sim2real-behav-policytopic-"))["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))

    policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Id": "owner-only",
            "Statement": [
                {
                    "Sid": "OwnerPublish",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
                    "Action": "SNS:Publish",
                    "Resource": arn,
                }
            ],
        },
        separators=(",", ":"),
    )
    sns.set_topic_attributes(TopicArn=arn, AttributeName="Policy", AttributeValue=policy)
    read_back = sns.get_topic_attributes(TopicArn=arn)["Attributes"]["Policy"]
    assert read_back == policy, f"Policy read back as {read_back!r}, expected {policy!r}"

    sns.delete_topic(TopicArn=arn)
    deadline = time.monotonic() + min(60.0, ctx.time_left())
    while True:
        try:
            sns.get_topic_attributes(TopicArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFound":
                raise
            break
        assert time.monotonic() < deadline, f"deleted topic {arn} is still readable"
        time.sleep(2)

    code, message = _error(lambda: sns.get_topic_attributes(TopicArn=arn))
    assert (code, message) == ("NotFound", "Topic does not exist"), (
        f"GetTopicAttributes on a deleted topic gave {code!r}: {message!r}"
    )
    code, message = _error(
        lambda: sns.set_topic_attributes(
            TopicArn=arn, AttributeName="Policy", AttributeValue=policy
        )
    )
    assert (code, message) == ("NotFound", "Topic does not exist"), (
        f"SetTopicAttributes on a deleted topic gave {code!r}: {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
