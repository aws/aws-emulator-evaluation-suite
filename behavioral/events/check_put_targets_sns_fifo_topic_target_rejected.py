"""put-targets-sns-fifo-topic-target-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-targets-sns-fifo-topic-target-rejected"
GROUP = "sns-target"
SERVICES = ["events"]


def _error(fn) -> tuple[str, str]:
    """Call fn(); return the AWS error (Code, Message) if it raised a ClientError. An unexpected
    SUCCESS raises, because an emulator ACCEPTING input real AWS refuses is the strongest signal
    available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutTargets refuses a FIFO SNS topic as a target, with ValidationException and its exact
    message, while the identical rule accepts a standard SNS topic."""
    events = ctx.client("events")
    sns = ctx.client("sns")

    fifo_topic_name = ctx.unique_name("sim2real-behav-topic-") + ".fifo"
    fifo_topic_arn = sns.create_topic(
        Name=fifo_topic_name,
        Attributes={"FifoTopic": "true", "ContentBasedDeduplication": "true"},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=fifo_topic_arn))

    std_topic_name = ctx.unique_name("sim2real-behav-topic-")
    std_topic_arn = sns.create_topic(
        Name=std_topic_name, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=std_topic_arn))

    bus_name = ctx.unique_name("sim2real-behav-bus-")
    events.create_event_bus(Name=bus_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus_name))

    rule_name = ctx.unique_name("sim2real-behav-rule-")
    events.put_rule(
        Name=rule_name, EventBusName=bus_name, EventPattern='{"source": ["sim2real.probe"]}',
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )

    def _cleanup_rule() -> None:
        ids = [t["Id"] for t in events.list_targets_by_rule(Rule=rule_name, EventBusName=bus_name)["Targets"]]
        if ids:
            events.remove_targets(Rule=rule_name, EventBusName=bus_name, Ids=ids)
        events.delete_rule(Name=rule_name, EventBusName=bus_name)

    ctx.on_cleanup(_cleanup_rule)

    code, message = _error(
        lambda: events.put_targets(
            Rule=rule_name,
            EventBusName=bus_name,
            Targets=[{"Id": "fifo-sns-target", "Arn": fifo_topic_arn}],
        )
    )
    assert (code, message) == (
        "ValidationException",
        "SNS FIFO is not a supported service for a target.",
    ), f"expected the FIFO SNS topic target to be refused, got {code!r} {message!r}"

    after_rejection = events.list_targets_by_rule(Rule=rule_name, EventBusName=bus_name)["Targets"]
    assert after_rejection == [], (
        f"the rejected PutTargets left a target registered: {after_rejection!r}"
    )

    # Positive control: the identical call against a standard SNS topic is accepted.
    put = events.put_targets(
        Rule=rule_name,
        EventBusName=bus_name,
        Targets=[{"Id": "std-sns-target", "Arn": std_topic_arn}],
    )
    assert put["FailedEntryCount"] == 0, f"PutTargets with a standard SNS topic failed: {put['FailedEntries']!r}"

    registered = events.list_targets_by_rule(Rule=rule_name, EventBusName=bus_name)["Targets"]
    assert [t["Id"] for t in registered] == ["std-sns-target"], (
        f"expected exactly the standard SNS topic target registered, got {registered!r}"
    )
    assert registered[0]["Arn"] == std_topic_arn, (
        f"registered target does not carry the standard topic's ARN: {registered[0]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
