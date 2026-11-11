"""set-topic-attributes-unknown-name-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-topic-attributes-unknown-name-fails"
GROUP = 'topic-attributes'
SERVICES = ['sns']


def _error(fn):
    """Call fn(); return the botocore error (Code, Message) if a ClientError was raised. An unexpected
    SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_topic(ctx, name=None):
    """Create a topic, register its teardown, and return its ARN."""
    sns = ctx.client("sns")
    name = name or ctx.unique_name("sim2real-behav-sns-topic-")
    arn = sns.create_topic(Name=name)["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return arn


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """[overly-permissive] SetTopicAttributes with an unknown AttributeName must be rejected,
    must not affect the topic's existing attributes, and a well-formed SetTopicAttributes call
    on the same topic must still succeed (positive control)."""
    sns = ctx.client("sns")
    arn = _create_topic(ctx)

    original_display_name = sns.get_topic_attributes(TopicArn=arn)["Attributes"]["DisplayName"]

    code, message = _error(
        lambda: sns.set_topic_attributes(
            TopicArn=arn, AttributeName="NotARealAttribute", AttributeValue="x"
        )
    )
    assert code == "InvalidParameter", f"expected InvalidParameter, got {code!r}"
    assert message == 'Invalid parameter: AttributeName', (
        f"expected the exact message 'Invalid parameter: AttributeName', got {message!r}"
    )

    unchanged_display_name = sns.get_topic_attributes(TopicArn=arn)["Attributes"]["DisplayName"]
    assert unchanged_display_name == original_display_name, (
        "topic attributes mutated despite rejected SetTopicAttributes call"
    )

    # positive control: a well-formed attribute update on the same topic still succeeds
    display_name = ctx.unique_name("sim2real-displayname-")
    sns.set_topic_attributes(TopicArn=arn, AttributeName="DisplayName", AttributeValue=display_name)
    fetched_display_name = sns.get_topic_attributes(TopicArn=arn)["Attributes"]["DisplayName"]
    assert fetched_display_name == display_name, (
        f"expected DisplayName {display_name!r}, got {fetched_display_name!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
