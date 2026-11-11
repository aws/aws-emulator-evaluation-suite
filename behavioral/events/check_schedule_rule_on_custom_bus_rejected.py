"""schedule-rule-on-custom-bus-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "schedule-rule-on-custom-bus-rejected"
GROUP = 'rule'
SERVICES = ['events']

_TAGS = [{"Key": "sim2real", "Value": "behavioral"}]


def _client_error(fn):
    """Call fn() and return its botocore Error dict; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected PutRule to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutRule with a ScheduleExpression on a custom bus is rejected with ValidationException
    (schedules are default-bus only) and creates no rule; a control pattern rule on that bus is
    created first and stays ENABLED, so the rejection is about the schedule."""
    ev = ctx.client("events")
    bus = ctx.unique_name("sim2real-behav-bus-")
    ev.create_event_bus(Name=bus, Tags=_TAGS)
    ctx.on_cleanup(lambda n=bus: ev.delete_event_bus(Name=n))

    control_name = ctx.unique_name("sim2real-behav-rule-control-")
    ev.put_rule(
        Name=control_name,
        EventPattern='{"source": ["sim2real.control"]}',
        EventBusName=bus,
        Tags=_TAGS,
    )
    ctx.on_cleanup(lambda n=control_name: ev.delete_rule(Name=n, EventBusName=bus, Force=True))
    control_desc = ev.describe_rule(Name=control_name, EventBusName=bus)
    assert control_desc["Name"] == control_name, (
        f"positive control rule did not register on the custom bus: {control_desc}"
    )

    rule_name = ctx.unique_name("sim2real-behav-rule-")
    error = _client_error(
        lambda: ev.put_rule(
            Name=rule_name,
            ScheduleExpression="rate(5 minutes)",
            EventBusName=bus,
            Tags=_TAGS,
        )
    )
    assert error.get("Code") == "ValidationException", (
        f"scheduled rule on a custom event bus was rejected with {error.get('Code')!r}, expected "
        f"'ValidationException': {error}"
    )
    expected_message = "ScheduleExpression is supported only on the default event bus."
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    rules = ev.list_rules(NamePrefix=rule_name, EventBusName=bus)["Rules"]
    assert rules == [], f"rejected scheduled rule must not be created: {rules}"

    still_there = ev.describe_rule(Name=control_name, EventBusName=bus)
    assert still_there["State"] == "ENABLED", (
        f"positive control rule was affected by the rejected call: {still_there}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
