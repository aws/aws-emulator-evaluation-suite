"""publish-with-a-nonexistent-kms-alias-rejected-kmsnotfound."""

from __future__ import annotations

import re

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "publish-with-a-nonexistent-kms-alias-rejected-kmsnotfound"
GROUP = "kms-aliases"
SERVICES = ["kms", "sns"]

_REAL_ALIAS = "alias/aws/sns"
_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"


def _partition(arn: str) -> str:
    """The partition out of an ARN this check already received — never a literal 'aws'."""
    parts = arn.split(":")
    assert len(parts) > 2 and parts[0] == "arn" and parts[1], (
        f"{arn!r} is not an ARN from which a partition can be read"
    )
    return parts[1]


def _teardown(undo, *not_found: str):
    def run() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:data", "dp:api")
def run(ctx) -> None:
    """A KMS alias that was never created is NotFoundException on DescribeKey; Publish on a
    topic whose KMS key attribute names it fails with KMSNotFound, and the same topic under
    alias/aws/sns publishes."""
    sns = ctx.client("sns")
    kms = ctx.client("kms")

    name = ctx.unique_name("sim2real-ssns-badalias-")
    topic = sns.create_topic(Name=name)["TopicArn"]
    ctx.on_cleanup(_teardown(lambda: sns.delete_topic(TopicArn=topic), "NotFound"))
    partition = _partition(topic)

    bogus_alias = ctx.unique_name("alias/sim2real-noalias-")
    sns.set_topic_attributes(
        TopicArn=topic, AttributeName="KmsMasterKeyId", AttributeValue=bogus_alias
    )
    attrs = sns.get_topic_attributes(TopicArn=topic)["Attributes"]
    stored = attrs.get("KmsMasterKeyId")
    assert stored == bogus_alias, (
        f"GetTopicAttributes KMS key attribute: expected {bogus_alias!r}, got {stored!r}"
    )

    try:
        kms.describe_key(KeyId=bogus_alias)
        raise AssertionError(f"DescribeKey({bogus_alias!r}) unexpectedly succeeded")
    except ClientError as exc:
        err = exc.response.get("Error", {})
        want = (
            "NotFoundException",
            f"Alias arn:{partition}:kms:{ctx.region}:{ctx.account}:{bogus_alias} is not found.",
        )
        assert (err.get("Code"), err.get("Message")) == want, (
            f"DescribeKey({bogus_alias!r}): expected {want!r}, got {(err.get('Code'), err.get('Message'))!r}"
        )

    try:
        sns.publish(TopicArn=topic, Message="sim2real nonexistent-alias probe")
        raise AssertionError(
            f"Publish under the nonexistent alias {bogus_alias!r} unexpectedly succeeded"
        )
    except ClientError as exc:
        err = exc.response.get("Error", {})
        want_message = (
            f"Alias arn:{partition}:kms:{ctx.region}:{ctx.account}:{bogus_alias} is not found. "
            "(Service: AWSKMS; Status Code: 400; Error Code: NotFoundException; "
            "Request ID: <id>; Proxy: null)"
        )
        got_message = re.sub(
            r"Request ID: [0-9a-f-]+;", "Request ID: <id>;", err.get("Message") or ""
        )
        assert (err.get("Code"), got_message) == ("KMSNotFound", want_message), (
            f"Publish under {bogus_alias!r}: expected ('KMSNotFound', {want_message!r}), got "
            f"{(err.get('Code'), got_message)!r}"
        )

    sns.set_topic_attributes(
        TopicArn=topic, AttributeName="KmsMasterKeyId", AttributeValue=_REAL_ALIAS
    )
    published = sns.publish(TopicArn=topic, Message="sim2real control probe")
    assert re.fullmatch(_UUID, published.get("MessageId") or ""), (
        f"Publish under the real alias {_REAL_ALIAS!r}: expected a UUID MessageId, got {published!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
