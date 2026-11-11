"""fifo-topic-attributes-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "fifo-topic-attributes-roundtrip"
GROUP = 'topic-lifecycle'
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

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A FIFO topic reports FifoTopic=true, defaults ContentBasedDeduplication to false, and that
    attribute round-trips through SetTopicAttributes independently of CreateTopic."""
    ev = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-sns-fifo-ok-") + ".fifo"
    arn = _create_topic(
        ev, ctx, name, attributes={"FifoTopic": "true"},
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    attrs = ev.get_topic_attributes(TopicArn=arn)["Attributes"]
    assert attrs.get("FifoTopic") == "true", f"expected FifoTopic=true, got {attrs.get('FifoTopic')}"
    assert attrs.get("ContentBasedDeduplication") == "false", (
        f"expected ContentBasedDeduplication default false, got {attrs.get('ContentBasedDeduplication')}"
    )

    ev.set_topic_attributes(TopicArn=arn, AttributeName="ContentBasedDeduplication", AttributeValue="true")
    turned_on = ev.get_topic_attributes(TopicArn=arn)["Attributes"]
    assert turned_on.get("ContentBasedDeduplication") == "true", (
        f"expected ContentBasedDeduplication=true after SetTopicAttributes, got {turned_on.get('ContentBasedDeduplication')}"
    )

    ev.set_topic_attributes(TopicArn=arn, AttributeName="ContentBasedDeduplication", AttributeValue="false")
    turned_off = ev.get_topic_attributes(TopicArn=arn)["Attributes"]
    assert turned_off.get("ContentBasedDeduplication") == "false", (
        f"expected ContentBasedDeduplication=false after resetting via SetTopicAttributes, got {turned_off.get('ContentBasedDeduplication')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
