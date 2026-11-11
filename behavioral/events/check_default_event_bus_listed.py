"""default-event-bus-listed."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "default-event-bus-listed"
GROUP = 'event-bus'
SERVICES = ['events']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListEventBuses always includes the account's default event bus, and its entry
    is distinguished from a created bus: an Arn scoped to this account/region, and no
    CreationTime (the default bus was never explicitly created)."""
    ev = ctx.client("events")
    account = ctx.client("sts").get_caller_identity()["Account"]
    buses = {}
    kwargs = {}
    while True:
        resp = ev.list_event_buses(**kwargs)
        buses.update({b["Name"]: b for b in resp.get("EventBuses", [])})
        if not resp.get("NextToken"):
            break
        kwargs = {"NextToken": resp["NextToken"]}
    assert "default" in buses, f"default event bus must always be present, got {sorted(buses)}"
    default_bus = buses["default"]
    expected_arn_suffix = f":{ctx.region}:{account}:event-bus/default"
    assert default_bus.get("Arn", "").endswith(expected_arn_suffix), (
        f"default bus Arn must be scoped to this account/region, got {default_bus.get('Arn')}"
    )
    assert "CreationTime" not in default_bus, (
        f"the default bus was never explicitly created and must carry no CreationTime, "
        f"got {default_bus}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
