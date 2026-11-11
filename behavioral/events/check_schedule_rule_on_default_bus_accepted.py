"""schedule-rule-on-default-bus-accepted."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "schedule-rule-on-default-bus-accepted"
GROUP = 'rule'
SERVICES = ['events']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A valid ScheduleExpression rule IS accepted on the default bus and DescribeRule echoes the expression back with no EventPattern."""
    ev = ctx.client("events")
    rule_name = ctx.unique_name("sim2real-behav-rule-")
    ev.put_rule(
        Name=rule_name,
        ScheduleExpression="rate(5 minutes)",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda n=rule_name: ev.delete_rule(Name=n, Force=True))

    desc = ev.describe_rule(Name=rule_name)
    assert desc["ScheduleExpression"] == "rate(5 minutes)", f"unexpected schedule: {desc}"
    assert not desc.get("EventPattern"), f"schedule rule should have no EventPattern: {desc}"
    assert desc["State"] == "ENABLED", f"PutRule with no explicit State must default to ENABLED, got {desc.get('State')!r}: {desc}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
