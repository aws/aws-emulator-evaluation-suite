"""delete-rule-without-event-bus-name-leaves-custom-bus-rule-in-place."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-rule-without-event-bus-name-leaves-custom-bus-rule-in-place"
GROUP = 'rule'
SERVICES = ['events']


def _error(fn):
    """The (Error.Code, Error.Message) ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteRule without EventBusName succeeds but leaves a same-named custom-bus rule intact;
    DeleteRule with the bus ARN removes it, and DescribeRule then names the custom bus.
    """
    ev = ctx.client("events")
    bus = ctx.unique_name("sim2real-behav-bus-")
    bus_arn = ev.create_event_bus(Name=bus, Tags=[{"Key": "sim2real", "Value": "behavioral"}])["EventBusArn"]
    ctx.on_cleanup(lambda: ev.delete_event_bus(Name=bus))

    rule = ctx.unique_name("sim2real-behav-rule-")
    pattern = {"source": ["sim2real.survivor"]}
    ev.put_rule(Name=rule, EventBusName=bus, EventPattern=json.dumps(pattern))
    ctx.on_cleanup(lambda: ev.delete_rule(Name=rule, EventBusName=bus))

    # Targets the default bus, where the rule is absent; DeleteRule of an absent rule succeeds.
    ev.delete_rule(Name=rule)

    survivor = ev.describe_rule(Name=rule, EventBusName=bus)
    assert survivor["Name"] == rule, f"DescribeRule on the custom bus returned Name {survivor.get('Name')!r}"
    assert json.loads(survivor["EventPattern"]) == pattern, (
        f"the custom-bus rule's pattern after a default-bus DeleteRule is {survivor['EventPattern']!r}"
    )
    listed = [r["Name"] for r in ev.list_rules(EventBusName=bus, NamePrefix=rule)["Rules"]]
    assert listed == [rule], f"ListRules on the custom bus after a default-bus DeleteRule shows {listed!r}"

    ev.delete_rule(Name=rule, EventBusName=bus_arn)
    code, message = _error(lambda: ev.describe_rule(Name=rule, EventBusName=bus))
    assert code == "ResourceNotFoundException", f"DescribeRule after the bus-scoped DeleteRule gave {code!r}"
    assert message == f"Rule {rule} does not exist on EventBus {bus}.", (
        f"DescribeRule after the bus-scoped DeleteRule said {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
