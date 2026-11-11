"""put-rule-default-state-enabled."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-rule-default-state-enabled"
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
    """PutRule without an explicit State defaults the rule to ENABLED, while a sibling rule
    created with State='DISABLED' stays DISABLED, so ENABLED is not merely hardcoded."""
    ev = ctx.client("events")
    bus = ctx.unique_name("sim2real-behav-bus-")
    ev.create_event_bus(Name=bus)
    ctx.on_cleanup(lambda n=bus: ev.delete_event_bus(Name=n))

    rule = ctx.unique_name("sim2real-behav-rule-")
    ev.put_rule(Name=rule, EventBusName=bus, EventPattern=json.dumps({'source': ['test.source']}))
    ctx.on_cleanup(lambda n=rule, b=bus: _cleanup_rule(ev, n, b))
    desc = ev.describe_rule(Name=rule, EventBusName=bus)
    assert desc["State"] == "ENABLED", f"rule created without State must default to ENABLED, got {desc.get('State')!r}"

    disabled_rule = ctx.unique_name("sim2real-behav-rule-disabled-")
    ev.put_rule(Name=disabled_rule, EventBusName=bus, EventPattern=json.dumps({'source': ['test.source']}), State='DISABLED')
    ctx.on_cleanup(lambda n=disabled_rule, b=bus: _cleanup_rule(ev, n, b))
    disabled_desc = ev.describe_rule(Name=disabled_rule, EventBusName=bus)
    assert disabled_desc["State"] == "DISABLED", f"rule created with State='DISABLED' must stay DISABLED, got {disabled_desc.get('State')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
