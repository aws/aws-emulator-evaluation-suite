"""event-bus-dead-letter-config-rejects-non-sqs-arns-and-keeps-prior-config."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "event-bus-dead-letter-config-rejects-non-sqs-arns-and-keeps-prior-config"
GROUP = "event-bus"
SERVICES = ["events"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Bus DeadLetterConfig must be an SQS ARN: SNS and non-ARN values are refused on update (prior
    config kept) and create (no bus); an SQS ARN of a nonexistent queue is stored verbatim.
    """
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    queue = ctx.unique_name("sim2real-behav-dlq-")
    queue_url = sqs.create_queue(QueueName=queue, tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    bus = ctx.unique_name("sim2real-behav-bus-")
    events.create_event_bus(Name=bus, DeadLetterConfig={"Arn": queue_arn}, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus))
    assert _dlq(events, bus) == {"Arn": queue_arn}, "positive control: the SQS dead-letter queue must be stored"

    sns_arn = f"arn:aws:sns:{ctx.region}:{ctx.account}:{ctx.unique_name('sim2real-behav-topic-')}"
    refusals = [
        ({"Arn": sns_arn}, "sns is not supported as a dead letter resource."),
        ({"Arn": "sim2real-not-an-arn"},
         "Parameter sim2real-not-an-arn is not valid. Reason: Provided Arn is not in correct format."),
    ]
    for config, expected in refusals:
        code, message = _error(lambda c=config: events.update_event_bus(Name=bus, DeadLetterConfig=c))
        assert (code, message) == ("ValidationException", expected), (
            f"UpdateEventBus DeadLetterConfig={config!r} gave {code!r} {message!r}, expected {expected!r}"
        )
        assert _dlq(events, bus) == {"Arn": queue_arn}, (
            f"the refused update {config!r} must leave the prior dead-letter queue in place"
        )

    refused_bus = ctx.unique_name("sim2real-behav-bus-")
    ctx.on_cleanup(lambda: _delete_if_present(events, refused_bus))
    code, message = _error(lambda: events.create_event_bus(Name=refused_bus, DeadLetterConfig={"Arn": sns_arn}))
    assert (code, message) == ("ValidationException", "sns is not supported as a dead letter resource."), (
        f"CreateEventBus with an SNS dead-letter ARN gave {code!r} {message!r}"
    )
    gone = _error(lambda: events.describe_event_bus(Name=refused_bus))
    assert gone == ("ResourceNotFoundException", f"Event bus {refused_bus} does not exist."), (
        f"the refused CreateEventBus must create nothing; DescribeEventBus gave {gone!r}"
    )

    missing_queue = f"arn:aws:sqs:{ctx.region}:{ctx.account}:{ctx.unique_name('sim2real-behav-noq-')}"
    updated = events.update_event_bus(Name=bus, DeadLetterConfig={"Arn": missing_queue})
    assert updated.get("DeadLetterConfig") == {"Arn": missing_queue}, (
        f"an SQS ARN is accepted without an existence check; UpdateEventBus answered {updated.get('DeadLetterConfig')!r}"
    )
    assert _dlq(events, bus) == {"Arn": missing_queue}, "the accepted dead-letter ARN must be stored verbatim"


def _dlq(events, bus: str):
    return events.describe_event_bus(Name=bus).get("DeadLetterConfig")


def _delete_if_present(events, name: str) -> None:
    """Delete the bus if a refused CreateEventBus created it anyway."""
    try:
        events.describe_event_bus(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    events.delete_event_bus(Name=name)


def _error(fn) -> tuple[str, str]:
    """(code, message) of a call that must fail; an unexpected success raises, naming the result."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
