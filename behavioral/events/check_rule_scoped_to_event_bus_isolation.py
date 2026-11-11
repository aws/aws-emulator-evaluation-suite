"""rule-scoped-to-event-bus-isolation."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rule-scoped-to-event-bus-isolation"
GROUP = 'event-bus'
SERVICES = ['events']

def _client_error(fn):
    """Call fn(); return the botocore Error dict it raised. An unexpected SUCCESS raises, so a
    target that accepts what AWS refuses is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")

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

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A rule created on a custom event bus is not visible via ListRules on the default bus, but is visible when listing its own bus -- rules are bus-scoped."""
    ev = ctx.client("events")
    tags = [{"Key": "sim2real-check", "Value": CHECK}]
    bus_name = ctx.unique_name("sim2real-behav-bus-")
    ev.create_event_bus(Name=bus_name, Tags=tags)
    ctx.on_cleanup(lambda n=bus_name: ev.delete_event_bus(Name=n))

    rule_name = ctx.unique_name("sim2real-behav-rule-")
    pattern = json.dumps({"source": ["x"]})
    ev.put_rule(
        Name=rule_name,
        EventPattern=pattern,
        EventBusName=bus_name,
        Tags=tags,
    )
    ctx.on_cleanup(lambda n=rule_name, b=bus_name: _cleanup_rule(ev, n, b))

    # Positive control: DescribeRule itself works and returns the bus-qualified rule
    # when the caller names the owning bus -- without this, a 404 in the negative
    # below would be indistinguishable from DescribeRule being broken outright.
    described = ev.describe_rule(Name=rule_name, EventBusName=bus_name)
    assert described.get("EventBusName") == bus_name, (
        f"describing bus-scoped rule with its own EventBusName must succeed and echo it, "
        f"got EventBusName={described.get('EventBusName')!r}"
    )
    assert described.get("EventPattern") == pattern, (
        f"describing bus-scoped rule with its own EventBusName must return the rule's own "
        f"pattern, expected {pattern!r} got {described.get('EventPattern')!r}"
    )

    default_rules = {r["Name"] for r in ev.list_rules(NamePrefix=rule_name)["Rules"]}
    assert rule_name not in default_rules, (
        "rule created on custom bus must not appear when listing the default bus"
    )

    custom_rules = {
        r["Name"]
        for r in ev.list_rules(NamePrefix=rule_name, EventBusName=bus_name)["Rules"]
    }
    assert rule_name in custom_rules, "rule must be visible when listing its own bus"

    err = _client_error(lambda: ev.describe_rule(Name=rule_name))
    assert err.get("Code") == "ResourceNotFoundException", (
        f"describing bus-scoped rule without EventBusName must 404, got {err}"
    )
    expected_message = f"Rule {rule_name} does not exist on EventBus default."
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
