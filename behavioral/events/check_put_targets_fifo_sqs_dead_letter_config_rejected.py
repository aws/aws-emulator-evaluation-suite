"""put-targets-fifo-sqs-dead-letter-config-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-targets-fifo-sqs-dead-letter-config-rejected"
GROUP = "dead-letter-queue"
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


def _queue_arn(sqs, url: str) -> str:
    return sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutTargets refuses a target whose DeadLetterConfig names a FIFO queue, with
    ValidationException and its exact message, while the same target with a standard queue as its
    dead-letter queue is accepted."""
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    std_target_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-tgt-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=std_target_url))
    std_target_arn = _queue_arn(sqs, std_target_url)

    std_dlq_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-dlq-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=std_dlq_url))
    std_dlq_arn = _queue_arn(sqs, std_dlq_url)

    fifo_dlq_name = ctx.unique_name("sim2real-behav-dlq-") + ".fifo"
    fifo_dlq_url = sqs.create_queue(
        QueueName=fifo_dlq_name,
        Attributes={"FifoQueue": "true", "ContentBasedDeduplication": "true"},
        tags={"sim2real": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=fifo_dlq_url))
    fifo_dlq_arn = _queue_arn(sqs, fifo_dlq_url)

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
            Targets=[
                {
                    "Id": "fifo-dlq-target",
                    "Arn": std_target_arn,
                    "DeadLetterConfig": {"Arn": fifo_dlq_arn},
                }
            ],
        )
    )
    assert (code, message) == (
        "ValidationException",
        "SQS FIFO is not supported by Dead Letter Queues.",
    ), f"expected the FIFO dead-letter queue to be refused, got {code!r} {message!r}"

    after_rejection = events.list_targets_by_rule(Rule=rule_name, EventBusName=bus_name)["Targets"]
    assert after_rejection == [], (
        f"the rejected PutTargets left a target registered: {after_rejection!r}"
    )

    # Positive control: the identical target with a standard-queue dead-letter config is accepted.
    put = events.put_targets(
        Rule=rule_name,
        EventBusName=bus_name,
        Targets=[
            {
                "Id": "std-dlq-target",
                "Arn": std_target_arn,
                "DeadLetterConfig": {"Arn": std_dlq_arn},
            }
        ],
    )
    assert put["FailedEntryCount"] == 0, f"PutTargets with a standard DLQ failed: {put['FailedEntries']!r}"

    registered = events.list_targets_by_rule(Rule=rule_name, EventBusName=bus_name)["Targets"]
    assert [t["Id"] for t in registered] == ["std-dlq-target"], (
        f"expected exactly the standard-DLQ target registered, got {registered!r}"
    )
    assert registered[0]["DeadLetterConfig"]["Arn"] == std_dlq_arn, (
        f"registered target's DeadLetterConfig does not carry the standard queue's ARN: {registered[0]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
