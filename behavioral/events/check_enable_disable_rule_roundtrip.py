"""enable-disable-rule-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "enable-disable-rule-roundtrip"
GROUP = 'rule'
SERVICES = ['events']

def _cleanup_rule(client, name, bus):
    """Remove any attached targets, then delete the rule (delete_rule refuses a rule with targets)."""
    try:
        ids = [t["Id"] for t in client.list_targets_by_rule(Rule=name, EventBusName=bus).get("Targets", [])]
        if ids:
            client.remove_targets(Rule=name, Ids=ids, EventBusName=bus)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    client.delete_rule(Name=name, EventBusName=bus, Force=True)

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisableRule/EnableRule transition RuleState between ENABLED and DISABLED."""
    ev = ctx.client("events")
    bus = ctx.unique_name("sim2real-behav-bus-")
    ev.create_event_bus(Name=bus, Tags=[{"Key": "sim2real-check", "Value": CHECK}])
    ctx.on_cleanup(lambda n=bus: ev.delete_event_bus(Name=n))
    rule = ctx.unique_name("sim2real-behav-rule-")
    ev.put_rule(
        Name=rule,
        EventBusName=bus,
        EventPattern='{"source": ["sim2real.behav"]}',
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda n=rule, b=bus: _cleanup_rule(ev, n, b))
    ev.disable_rule(Name=rule, EventBusName=bus)
    desc = ev.describe_rule(Name=rule, EventBusName=bus)
    assert desc["State"] == "DISABLED", f"expected DISABLED after DisableRule, got {desc['State']}"
    ev.enable_rule(Name=rule, EventBusName=bus)
    desc = ev.describe_rule(Name=rule, EventBusName=bus)
    assert desc["State"] == "ENABLED", f"expected ENABLED after EnableRule, got {desc['State']}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
