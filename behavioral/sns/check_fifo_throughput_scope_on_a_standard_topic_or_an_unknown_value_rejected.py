"""fifo-throughput-scope-on-a-standard-topic-or-an-unknown-value-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "fifo-throughput-scope-on-a-standard-topic-or-an-unknown-value-rejected"
GROUP = "fifo-attributes"
SERVICES = ["sns"]


def _error(fn) -> tuple[str, str]:
    """(Code, Message) of the error ``fn`` raises; an unexpected success raises, naming it."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """FifoThroughputScope is refused on a standard topic and for an unknown value; a FIFO topic
    accepts MessageGroup but refuses the switch back to Topic, and no refusal changes the value."""
    sns = ctx.client("sns")
    std = sns.create_topic(Name=ctx.unique_name("sim2real-behav-sns-ftscope-"),
                           Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=std))
    fifo = sns.create_topic(Name=ctx.unique_name("sim2real-behav-sns-ftscope-") + ".fifo",
                            Attributes={"FifoTopic": "true"},
                            Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=fifo))

    code, message = _error(lambda: sns.set_topic_attributes(
        TopicArn=std, AttributeName="FifoThroughputScope", AttributeValue="MessageGroup"))
    assert (code, message) == ("InvalidParameter", "Invalid parameter: AttributeName"), (
        f"FifoThroughputScope on a standard topic gave {code!r}: {message!r}")
    std_attrs = sns.get_topic_attributes(TopicArn=std)["Attributes"]
    assert "FifoThroughputScope" not in std_attrs, (
        f"the refused write left FifoThroughputScope={std_attrs.get('FifoThroughputScope')!r} on a standard topic")

    sns.set_topic_attributes(TopicArn=fifo, AttributeName="FifoThroughputScope", AttributeValue="MessageGroup")
    assert sns.get_topic_attributes(TopicArn=fifo)["Attributes"].get("FifoThroughputScope") == "MessageGroup", (
        "a FIFO topic must accept FifoThroughputScope=MessageGroup")
    code, message = _error(lambda: sns.set_topic_attributes(
        TopicArn=fifo, AttributeName="FifoThroughputScope", AttributeValue="Partition"))
    assert (code, message) == ("InvalidParameter", "Invalid parameter: Invalid FifoThroughputScope: Partition"), (
        f"an unknown FifoThroughputScope value gave {code!r}: {message!r}")
    kept = sns.get_topic_attributes(TopicArn=fifo)["Attributes"].get("FifoThroughputScope")
    assert kept == "MessageGroup", f"the refused value changed FifoThroughputScope to {kept!r}"

    code, message = _error(lambda: sns.set_topic_attributes(
        TopicArn=fifo, AttributeName="FifoThroughputScope", AttributeValue="Topic"))
    assert (code, message) == ("InvalidParameter",
                               "Invalid parameter: Modifying FifoThroughputScope from MessageGroup to Topic is not supported"), (
        f"switching FifoThroughputScope back from MessageGroup to Topic gave {code!r}: {message!r}")
    final = sns.get_topic_attributes(TopicArn=fifo)["Attributes"].get("FifoThroughputScope")
    assert final == "MessageGroup", f"the refused switch back changed FifoThroughputScope to {final!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
