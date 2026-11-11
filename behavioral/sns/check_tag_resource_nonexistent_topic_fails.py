"""tag-resource-nonexistent-topic-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-nonexistent-topic-fails"
GROUP = 'tagging'
SERVICES = ['sns']


def _error(fn):
    """Call fn(); return botocore (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource succeeds on a live topic, fails ResourceNotFound once the topic is
    deleted, and succeeds again once a topic with the identical name — and therefore the
    identical ARN — is recreated."""
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-sns-topic-")
    arn = sns.create_topic(Name=name)["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))

    # positive control: tagging a live topic works and is visible via an independent read
    sns.tag_resource(ResourceArn=arn, Tags=[{"Key": "k", "Value": "v"}])
    live_tags = {t["Key"]: t["Value"] for t in sns.list_tags_for_resource(ResourceArn=arn)["Tags"]}
    assert live_tags.get("k") == "v", f"positive control failed to tag live topic, got {live_tags}"

    # break exactly one thing: the topic no longer exists
    sns.delete_topic(TopicArn=arn)

    code, message = _error(
        lambda: sns.tag_resource(ResourceArn=arn, Tags=[{"Key": "k2", "Value": "v2"}])
    )
    assert code == "ResourceNotFound", f"expected ResourceNotFound, got {code!r}"
    assert message == "Resource does not exist", f"unexpected ResourceNotFound message for TagResource: {message!r}"

    # effect absent via an independent read at the same ARN
    list_code, list_message = _error(lambda: sns.list_tags_for_resource(ResourceArn=arn))
    assert list_code == "ResourceNotFound", (
        f"expected ListTagsForResource to also see the topic gone, got {list_code!r}"
    )
    assert list_message == "Resource does not exist", (
        f"unexpected ResourceNotFound message for ListTagsForResource: {list_message!r}"
    )

    # restore: recreating the topic under the same name reuses the same ARN
    restored_arn = sns.create_topic(Name=name)["TopicArn"]
    assert restored_arn == arn, f"expected recreated topic to reuse ARN {arn}, got {restored_arn}"

    # the identical call now succeeds
    sns.tag_resource(ResourceArn=arn, Tags=[{"Key": "k2", "Value": "v2"}])
    restored_tags = {
        t["Key"]: t["Value"] for t in sns.list_tags_for_resource(ResourceArn=arn)["Tags"]
    }
    assert restored_tags.get("k2") == "v2", f"expected restored tagging to succeed, got {restored_tags}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
