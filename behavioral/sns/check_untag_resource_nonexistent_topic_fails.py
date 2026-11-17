"""untag-resource-nonexistent-topic-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "untag-resource-nonexistent-topic-fails"
GROUP = "tagging"
SERVICES = ["sns"]


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _tag_map(sns, arn: str) -> dict:
    return {t["Key"]: t["Value"] for t in sns.list_tags_for_resource(ResourceArn=arn)["Tags"]}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UntagResource on a deleted topic fails with ResourceNotFound, after removing a tag from
    the same topic while it was live, and succeeds again once the topic is recreated.
    """
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-sns-untag-")
    key = "sim2real-behav-sns-untag-key"

    arn = sns.create_topic(Name=name)["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    sns.tag_resource(ResourceArn=arn, Tags=[{"Key": key, "Value": "live"}])

    # Positive control: UntagResource on a live topic actually removes the tag.
    live_before = _tag_map(sns, arn)
    assert live_before.get(key) == "live", f"positive control: expected tag {key!r}='live', got {live_before!r}"
    sns.untag_resource(ResourceArn=arn, TagKeys=[key])
    live_after = _tag_map(sns, arn)
    assert key not in live_after, f"positive control: expected {key!r} removed, still present in {live_after!r}"

    # Break exactly one thing: the topic no longer exists.
    sns.delete_topic(TopicArn=arn)
    gone_code, gone_message = _error(lambda: sns.get_topic_attributes(TopicArn=arn))
    assert gone_code == "NotFound", f"expected NotFound reading a deleted topic, got {gone_code!r}"
    assert gone_message == "Topic does not exist", (
        f"unexpected NotFound message reading a deleted topic: {gone_message!r}"
    )

    code, message = _error(lambda: sns.untag_resource(ResourceArn=arn, TagKeys=[key]))
    assert code == "ResourceNotFound", f"UntagResource on a deleted topic: expected ResourceNotFound, got {code!r}"
    assert message == "Resource does not exist", (
        f"unexpected ResourceNotFound message for UntagResource on a deleted topic: {message!r}"
    )

    # Restore: SNS topic ARNs are deterministic on account+region+name, so recreating reuses the
    # ARN already registered for cleanup above.
    new_arn = sns.create_topic(Name=name)["TopicArn"]
    assert new_arn == arn, f"expected the recreated topic to reuse the ARN, got {new_arn!r} vs {arn!r}"
    sns.tag_resource(ResourceArn=new_arn, Tags=[{"Key": key, "Value": "restored"}])

    restored_before = _tag_map(sns, new_arn)
    assert restored_before.get(key) == "restored", (
        f"expected the recreated topic to carry tag {key!r}='restored', got {restored_before!r}"
    )
    sns.untag_resource(ResourceArn=new_arn, TagKeys=[key])
    restored_after = _tag_map(sns, new_arn)
    assert key not in restored_after, (
        f"expected UntagResource to succeed again on the recreated topic, still present in {restored_after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
