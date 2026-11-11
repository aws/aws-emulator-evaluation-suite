"""topic-set-attribute-immutable-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "topic-set-attribute-immutable-rejected"
GROUP = 'overly-permissive'
SERVICES = ['sns']

def _create_topic(client, ctx, name, attributes=None, tags=None):
    """CreateTopic + register best-effort DeleteTopic cleanup; returns the TopicArn."""
    kwargs = {"Name": name}
    if attributes:
        kwargs["Attributes"] = attributes
    if tags:
        kwargs["Tags"] = tags
    arn = client.create_topic(**kwargs)["TopicArn"]
    ctx.on_cleanup(lambda: client.delete_topic(TopicArn=arn))
    return arn

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SetTopicAttributes rejects attempts to flip FifoTopic post-creation, leaves the
    attribute unchanged, and a sibling SetTopicAttributes call for a different, mutable
    attribute on the same topic still succeeds (overly-permissive check)."""
    ev = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-sns-immut-")
    arn = _create_topic(
        ev, ctx, name,
        tags=[{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}],
    )

    # real SNS omits FifoTopic from GetTopicAttributes entirely for a standard topic
    # rather than reporting it as "false" -- absence means false, per the API's own docs
    original_fifo = ev.get_topic_attributes(TopicArn=arn)["Attributes"].get("FifoTopic", "false")

    try:
        result = ev.set_topic_attributes(TopicArn=arn, AttributeName='FifoTopic', AttributeValue='true')
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    else:
        raise AssertionError(f"SetTopicAttributes FifoTopic=true SUCCEEDED: {result!r}")
    assert code == "InvalidParameter", (
        f"expected InvalidParameter when mutating immutable FifoTopic attribute, got {code}"
    )
    assert message == "Invalid parameter: AttributeName", (
        f"unexpected refusal message when mutating FifoTopic: {message!r}"
    )

    unchanged_fifo = ev.get_topic_attributes(TopicArn=arn)["Attributes"].get("FifoTopic", "false")
    assert unchanged_fifo == original_fifo, (
        f"FifoTopic attribute mutated despite rejected SetTopicAttributes call: "
        f"expected {original_fifo!r}, got {unchanged_fifo!r}"
    )

    # positive control: a well-formed attribute update on the same topic still succeeds
    display_name = ctx.unique_name("sim2real-displayname-")
    ev.set_topic_attributes(TopicArn=arn, AttributeName="DisplayName", AttributeValue=display_name)
    fetched_display_name = ev.get_topic_attributes(TopicArn=arn)["Attributes"]["DisplayName"]
    assert fetched_display_name == display_name, (
        f"expected DisplayName update to persist, got {fetched_display_name!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
