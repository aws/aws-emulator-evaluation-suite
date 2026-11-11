"""eventbridge-put-targets-invalid-queue-arn-rejected."""

from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eventbridge-put-targets-invalid-queue-arn-rejected"

GROUP = "overly-permissive"

SERVICES = ["events", "s3", "sqs"]

_MANAGED_TAG_KEY = "sim2real:managed"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutTargets rejects a malformed target ARN with ValidationException and its exact message
    and attaches no target of that batch, while the well-formed target alone is accepted."""
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    queue_name = ctx.unique_name("queue-")
    queue_url = sqs.create_queue(
        QueueName=queue_name, tags={_MANAGED_TAG_KEY: "true"}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    bus_name = ctx.unique_name("bus-")
    events.create_event_bus(
        Name=bus_name, Tags=[{"Key": _MANAGED_TAG_KEY, "Value": "true"}]
    )
    ctx.on_cleanup(lambda: ctx.client("events").delete_event_bus(Name=bus_name))

    rule_name = ctx.unique_name("rule-badarn-")
    events.put_rule(
        Name=rule_name,
        EventBusName=bus_name,
        EventPattern=json.dumps(
            {"source": ["app.orders"], "detail-type": ["OrderPlaced"]}
        ),
        Tags=[{"Key": _MANAGED_TAG_KEY, "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _cleanup_rule(ctx, rule_name, bus_name))

    err = _client_error(
        lambda: events.put_targets(
            Rule=rule_name,
            EventBusName=bus_name,
            Targets=[
                {"Id": "good-target", "Arn": queue_arn},
                {"Id": "bad-target", "Arn": "not-an-arn-at-all"},
            ],
        )
    )
    assert err == ("ValidationException", _BAD_ARN_MESSAGE), (
        f"PutTargets must reject a syntactically invalid target ARN with "
        f"ValidationException {_BAD_ARN_MESSAGE!r}, got {err!r}"
    )

    after_reject = events.list_targets_by_rule(Rule=rule_name, EventBusName=bus_name)[
        "Targets"
    ]
    assert after_reject == [], (
        "a rejected PutTargets must not partially apply -- expected no targets "
        f"attached, found {after_reject}"
    )

    ok = events.put_targets(
        Rule=rule_name,
        EventBusName=bus_name,
        Targets=[{"Id": "good-target", "Arn": queue_arn}],
    )
    assert ok.get("FailedEntryCount", 1) == 0, (
        "the identical well-formed SQS target must be accepted once the "
        f"malformed ARN is removed from the batch: {ok}"
    )
    after_accept = {
        t["Id"]
        for t in events.list_targets_by_rule(Rule=rule_name, EventBusName=bus_name)[
            "Targets"
        ]
    }
    assert after_accept == {"good-target"}, (
        f"expected exactly the well-formed target registered, got {after_accept}"
    )


_BAD_ARN_MESSAGE = "Parameter not-an-arn-at-all is not valid. Reason: Provided Arn is not in correct format."


def _client_error(fn) -> tuple[str, str]:
    """(error code, message) of a call expected to fail; RAISES if the call succeeds."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result}")


def _cleanup_rule(ctx, rule_name: str, bus_name: str) -> None:
    """Remove any attached targets, then delete the rule (DeleteRule refuses a rule with targets)."""
    events = ctx.client("events")
    try:
        targets = events.list_targets_by_rule(
            Rule=rule_name, EventBusName=bus_name
        ).get("Targets", [])
        if targets:
            events.remove_targets(
                Rule=rule_name, EventBusName=bus_name, Ids=[t["Id"] for t in targets]
            )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    events.delete_rule(Name=rule_name, EventBusName=bus_name, Force=True)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
