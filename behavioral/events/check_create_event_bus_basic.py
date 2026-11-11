"""create-event-bus-basic."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "create-event-bus-basic"
GROUP = 'event-bus'
SERVICES = ['events']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateEventBus creates a bus immediately visible via DescribeEventBus."""
    ev = ctx.client("events")
    name = ctx.unique_name("sim2real-behav-bus-")
    resp = ev.create_event_bus(Name=name, Tags=[{"Key": "sim2real", "Value": "1"}])
    ctx.on_cleanup(lambda n=name: ev.delete_event_bus(Name=n))
    assert resp.get("EventBusArn"), "CreateEventBus must return EventBusArn"
    desc = ev.describe_event_bus(Name=name)
    assert desc["Name"] == name, f"DescribeEventBus Name must echo {name!r}, got {desc.get('Name')!r}"
    assert desc["Arn"] == resp["EventBusArn"], (
        f"DescribeEventBus Arn must match CreateEventBus's EventBusArn "
        f"{resp['EventBusArn']!r}, got {desc.get('Arn')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
