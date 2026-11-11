"""put-rule-invalid-pattern-fails."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-rule-invalid-pattern-fails"
GROUP = 'rule'
SERVICES = ['events']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutRule rejects malformed EventPattern JSON with InvalidEventPatternException, leaves no rule
    behind, and a valid pattern under the same name is then accepted and round-trips."""
    ev = ctx.client("events")
    bus = ctx.unique_name("sim2real-behav-bus-")
    ev.create_event_bus(Name=bus, Tags=[{"Key": "sim2real-check", "Value": CHECK}])
    ctx.on_cleanup(lambda n=bus: ev.delete_event_bus(Name=n))
    rule = ctx.unique_name("sim2real-behav-rule-")

    bad_pattern = "{not valid json"
    err = _client_error(lambda: ev.put_rule(Name=rule, EventBusName=bus, EventPattern=bad_pattern))
    assert err.get("Code") == "InvalidEventPatternException", (
        f"PutRule must reject malformed EventPattern JSON: expected InvalidEventPatternException, "
        f"got {err}"
    )
    expected_message = (
        "Event pattern is not valid. Reason: Unexpected character ('n' (code 110)): was expecting "
        f"double-quote to start field name\n at [Source: (String)\"{bad_pattern}\"; line: 1, column: 2]"
    )
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    # Effect absent: a refused PutRule must not have created a rule under that name.
    listed = [r["Name"] for r in ev.list_rules(EventBusName=bus, NamePrefix=rule).get("Rules", [])]
    assert listed == [], (
        f"PutRule rejected malformed EventPattern but ListRules(NamePrefix={rule!r}) returned "
        f"{listed}; a refused create must leave no rule behind"
    )
    describe_err = _client_error(lambda: ev.describe_rule(Name=rule, EventBusName=bus))
    assert describe_err.get("Code") == "ResourceNotFoundException", (
        f"PutRule rejected malformed EventPattern but DescribeRule({rule!r}) returned "
        f"{describe_err} instead of ResourceNotFoundException"
    )
    expected_describe_message = f"Rule {rule} does not exist on EventBus {bus}."
    assert describe_err.get("Message") == expected_describe_message, (
        f"expected message {expected_describe_message!r}, got {describe_err.get('Message')!r}"
    )

    # Positive control, same bus and same rule name: a well-formed pattern is accepted and
    # round-trips byte-identically through DescribeRule.
    good_pattern = json.dumps({"source": ["aws.ec2"]})
    ev.put_rule(Name=rule, EventBusName=bus, EventPattern=good_pattern)
    ctx.on_cleanup(lambda n=rule, b=bus: ev.delete_rule(Name=n, EventBusName=b))
    described = ev.describe_rule(Name=rule, EventBusName=bus)
    assert described.get("EventPattern") == good_pattern, (
        f"positive control: PutRule with a well-formed pattern under the same name that was just "
        f"refused must round-trip through DescribeRule; got {described.get('EventPattern')!r}, "
        f"submitted {good_pattern!r}"
    )


def _client_error(call) -> dict:
    """Botocore Error dict of a call that must fail; an unexpected success raises."""
    try:
        result = call()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
