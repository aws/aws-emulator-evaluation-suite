"""delete-event-bus-removes-resource."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-event-bus-removes-resource"
GROUP = 'event-bus'
SERVICES = ['events']


def _err(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteEventBus removes the bus: an independent DescribeEventBus 404s, a
    PutRule targeting the dead id is rejected too, and the freed name is
    reusable for a fresh CreateEventBus.
    """
    ev = ctx.client("events")
    name = ctx.unique_name("sim2real-behav-bus-")
    ev.create_event_bus(Name=name, Tags=[{"Key": "sim2real-check", "Value": CHECK}])
    ctx.on_cleanup(lambda n=name: ev.delete_event_bus(Name=n))
    ev.delete_event_bus(Name=name)

    expected = ("ResourceNotFoundException", f"Event bus {name} does not exist.")
    describe_err = _err(lambda: ev.describe_event_bus(Name=name))
    assert describe_err == expected, (
        f"expected DescribeEventBus to fail with {expected} after delete, got {describe_err}"
    )

    rule = ctx.unique_name("sim2real-behav-rule-")
    put_rule_err = _err(lambda: ev.put_rule(Name=rule, EventBusName=name))
    assert put_rule_err == expected, (
        f"expected PutRule against the deleted bus to be rejected with {expected}, got {put_rule_err}"
    )

    resp = ev.create_event_bus(Name=name, Tags=[{"Key": "sim2real-check", "Value": CHECK}])
    assert resp.get("EventBusArn"), "the freed bus name must be reusable for a fresh CreateEventBus"
    desc = ev.describe_event_bus(Name=name)
    assert desc.get("Name") == name, f"recreated bus must describe under the same name, got {desc.get('Name')}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
