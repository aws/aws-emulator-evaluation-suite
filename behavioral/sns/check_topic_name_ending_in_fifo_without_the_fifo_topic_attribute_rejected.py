"""topic-name-ending-in-fifo-without-the-fifo-topic-attribute-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "topic-name-ending-in-fifo-without-the-fifo-topic-attribute-rejected"
GROUP = 'fifo'
SERVICES = ['sns']

_SCENARIO = "sns-fifo-suffix-standard-topic"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTopic of a .fifo name without FifoTopic=true is refused InvalidParameter and creates
    no topic (NotFound, not listed); with FifoTopic=true it creates a FIFO topic, and the
    unsuffixed name creates a standard one.
    """
    sns = ctx.client("sns")
    base = ctx.unique_name("sim2real-behav-sns-fifosfx-")
    name = base + ".fifo"

    for attrs in ({}, {"FifoTopic": "false"}):
        code, message = _error(lambda a=attrs: sns.create_topic(Name=name, Attributes=a,
                                                                Tags=_tags_kv()))
        assert (code, message) == ("InvalidParameter", "Invalid parameter: Topic Name"), (
            f"CreateTopic of a .fifo name with attributes {attrs!r}: got {code!r} {message!r}")

    standard = sns.create_topic(Name=base, Tags=_tags_kv())["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=standard))
    fifo_arn = standard + ".fifo"

    code, message = _error(lambda: sns.get_topic_attributes(TopicArn=fifo_arn))
    assert (code, message) == ("NotFound", "Topic does not exist"), (
        f"the refused name must not exist, GetTopicAttributes gave {code!r} {message!r}")
    listed = {t["TopicArn"] for page in sns.get_paginator("list_topics").paginate()
              for t in page["Topics"] if t["TopicArn"].startswith(standard)}
    assert listed == {standard}, (
        f"only the standard topic may list under this run's name, got {len(listed)} topic(s)")

    created = sns.create_topic(Name=name, Attributes={"FifoTopic": "true"},
                               Tags=_tags_kv())["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=created))
    assert created == fifo_arn, "the FIFO topic's ARN must be the standard topic's plus '.fifo'"
    fifo_attrs = sns.get_topic_attributes(TopicArn=created)["Attributes"]
    std_attrs = sns.get_topic_attributes(TopicArn=standard)["Attributes"]
    assert (fifo_attrs.get("FifoTopic"), std_attrs.get("FifoTopic", "false")) == ("true", "false"), (
        f"FifoTopic read back as {fifo_attrs.get('FifoTopic')!r} on the .fifo topic and "
        f"{std_attrs.get('FifoTopic')!r} on the standard one")


def _error(fn) -> tuple[str, str]:
    """The (Code, Message) of the ClientError ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real", "Value": _SCENARIO}, {"Key": "sim2real:managed", "Value": "true"}]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
