"""alias-aws-sns-names-an-enabled-aws-managed-key-and-its-topic-publishes."""

from __future__ import annotations

import re

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "alias-aws-sns-names-an-enabled-aws-managed-key-and-its-topic-publishes"
GROUP = "kms-aliases"
SERVICES = ["kms", "sns"]

_ALIAS = "alias/aws/sns"
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def _teardown(undo, *not_found: str):
    def run() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run


@tags("axis:happy-path", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A topic whose KMS key attribute is alias/aws/sns stores that alias and Publish returns a
    message id; the alias names an enabled, AWS-managed symmetric key whose only alias it is."""
    sns = ctx.client("sns")
    kms = ctx.client("kms")

    name = ctx.unique_name("sim2real-ssns-alias-")
    topic = sns.create_topic(Name=name)["TopicArn"]
    ctx.on_cleanup(_teardown(lambda: sns.delete_topic(TopicArn=topic), "NotFound"))

    sns.set_topic_attributes(TopicArn=topic, AttributeName="KmsMasterKeyId", AttributeValue=_ALIAS)
    attrs = sns.get_topic_attributes(TopicArn=topic)["Attributes"]
    stored = attrs.get("KmsMasterKeyId")
    assert stored == _ALIAS, (
        f"GetTopicAttributes KMS key attribute: expected {_ALIAS!r}, got {stored!r}"
    )

    published = sns.publish(TopicArn=topic, Message="sim2real alias/aws/sns first-use probe")
    assert _UUID.fullmatch(published.get("MessageId") or ""), (
        f"Publish under {_ALIAS!r}: expected a UUID MessageId, got {published!r}"
    )

    meta = kms.describe_key(KeyId=_ALIAS)["KeyMetadata"]
    assert meta["KeyManager"] == "AWS", f"DescribeKey({_ALIAS!r}) KeyManager {meta['KeyManager']!r}"
    assert meta["KeyState"] == "Enabled", f"DescribeKey({_ALIAS!r}) KeyState {meta['KeyState']!r}"
    assert meta["KeySpec"] == "SYMMETRIC_DEFAULT", (
        f"DescribeKey({_ALIAS!r}) KeySpec {meta['KeySpec']!r}"
    )
    key_id = meta["KeyId"]

    aliases = [a["AliasName"] for a in kms.list_aliases(KeyId=key_id)["Aliases"]]
    assert aliases == [_ALIAS], (
        f"ListAliases(KeyId={key_id!r}): expected [{_ALIAS!r}], got {aliases!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
