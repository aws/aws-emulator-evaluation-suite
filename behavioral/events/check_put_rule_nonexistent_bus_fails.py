"""put-rule-nonexistent-bus-fails."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-rule-nonexistent-bus-fails"
GROUP = 'rule'
SERVICES = ['events']

def _client_error(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError("expected a ClientError but the call succeeded")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """OVERLY-PERMISSIVE: PutRule referencing a nonexistent EventBusName must fail, must not
    silently land the rule on the default bus, and the identical call must succeed once that
    bus is created."""
    ev = ctx.client("events")
    pattern = json.dumps({"source": ["sim2real.behav"]})

    # positive control: PutRule against a bus that exists works at all, so a later rejection
    # is attributable to the missing bus and not to PutRule being rejected wholesale.
    control_bus = ctx.unique_name("sim2real-behav-ctrlbus-")
    ev.create_event_bus(Name=control_bus)
    ctx.on_cleanup(lambda n=control_bus: ev.delete_event_bus(Name=n))
    control_rule = ctx.unique_name("sim2real-behav-ctrlrule-")
    ev.put_rule(Name=control_rule, EventBusName=control_bus, EventPattern=pattern)
    ctx.on_cleanup(lambda n=control_rule, b=control_bus: ev.delete_rule(Name=n, EventBusName=b, Force=True))

    bus_name = ctx.unique_name("sim2real-behav-bus-")
    rule = ctx.unique_name("sim2real-behav-rule-")

    err = _client_error(lambda: ev.put_rule(Name=rule, EventBusName=bus_name, EventPattern=pattern))
    assert err.get("Code") == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {err}"
    expected_message = f"Event bus {bus_name} does not exist."
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    default_rules = {r["Name"] for r in ev.list_rules(NamePrefix=rule)["Rules"]}
    assert rule not in default_rules, (
        "PutRule rejected for a nonexistent bus must not silently create the rule on the default bus"
    )

    # restore: create the bus that was missing, then the identical call must now succeed.
    ev.create_event_bus(Name=bus_name)
    ctx.on_cleanup(lambda n=bus_name: ev.delete_event_bus(Name=n))
    ev.put_rule(Name=rule, EventBusName=bus_name, EventPattern=pattern)
    ctx.on_cleanup(lambda n=rule, b=bus_name: ev.delete_rule(Name=n, EventBusName=b, Force=True))

    restored_rules = {r["Name"] for r in ev.list_rules(NamePrefix=rule, EventBusName=bus_name)["Rules"]}
    assert rule in restored_rules, "identical PutRule call must succeed once its bus exists"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
