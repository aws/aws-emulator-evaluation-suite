"""custom-bus-rule-calls-without-event-bus-name-not-found."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "custom-bus-rule-calls-without-event-bus-name-not-found"
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeRule, ListTargetsByRule, PutTargets and DisableRule on a custom-bus rule without
    EventBusName fail with ResourceNotFoundException naming the default bus and attach nothing;
    with EventBusName as the bus ARN they succeed and DisableRule takes effect."""
    ev = ctx.client("events")
    bus = ctx.unique_name("sim2real-behav-bus-")
    bus_arn = ev.create_event_bus(Name=bus, Tags=[{"Key": "sim2real", "Value": "behavioral"}])["EventBusArn"]
    ctx.on_cleanup(lambda: ev.delete_event_bus(Name=bus))

    rule = ctx.unique_name("sim2real-behav-rule-")
    ev.put_rule(Name=rule, EventBusName=bus, EventPattern=json.dumps({"source": ["sim2real.scoped"]}))
    ctx.on_cleanup(lambda: ev.delete_rule(Name=rule, EventBusName=bus))

    partition = bus_arn.split(":")[1]
    target_arn = f"arn:{partition}:sqs:{ctx.region}:{ctx.account}:" + ctx.unique_name("sim2real-behav-q-")
    expected = f"Rule {rule} does not exist on EventBus default."

    calls = {
        "DescribeRule": lambda: ev.describe_rule(Name=rule),
        "ListTargetsByRule": lambda: ev.list_targets_by_rule(Rule=rule),
        "PutTargets": lambda: ev.put_targets(Rule=rule, Targets=[{"Id": "t1", "Arn": target_arn}]),
        "DisableRule": lambda: ev.disable_rule(Name=rule),
    }
    for op, fn in calls.items():
        code, message = _error(fn)
        assert code == "ResourceNotFoundException", f"{op} on a custom-bus rule without EventBusName gave {code!r}"
        assert message == expected, f"{op} on a custom-bus rule without EventBusName said {message!r}"

    on_bus = ev.describe_rule(Name=rule, EventBusName=bus_arn)
    assert on_bus["Name"] == rule and on_bus["EventBusName"] == bus, (
        f"DescribeRule by bus ARN returned Name/EventBusName "
        f"{on_bus.get('Name')!r}/{on_bus.get('EventBusName')!r}"
    )
    assert on_bus["State"] == "ENABLED", (
        f"the refused DisableRule changed the custom-bus rule to {on_bus['State']!r}"
    )
    assert ev.list_targets_by_rule(Rule=rule, EventBusName=bus_arn)["Targets"] == [], (
        "the refused PutTargets attached a target to the custom-bus rule"
    )

    ok = ev.put_targets(Rule=rule, EventBusName=bus_arn, Targets=[{"Id": "t1", "Arn": target_arn}])
    ctx.on_cleanup(lambda: ev.remove_targets(Rule=rule, EventBusName=bus, Ids=["t1"]))
    assert ok["FailedEntryCount"] == 0, f"PutTargets with the bus ARN was refused: {ok!r}"
    listed = [t["Id"] for t in ev.list_targets_by_rule(Rule=rule, EventBusName=bus)["Targets"]]
    assert listed == ["t1"], f"after PutTargets with the bus ARN the rule lists targets {listed!r}"

    ev.disable_rule(Name=rule, EventBusName=bus_arn)
    state = ev.describe_rule(Name=rule, EventBusName=bus)["State"]
    assert state == "DISABLED", f"DisableRule with the bus ARN left the rule {state!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
