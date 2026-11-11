"""put-rule-schedule-expression-grammar-rejection."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-rule-schedule-expression-grammar-rejection"
GROUP = 'rule'
SERVICES = ['events']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutRule rejects malformed rate()/cron() expressions (ValidationException), creating no rule.

    Valid forms are accepted and round-trip exactly through DescribeRule and ListRules.

    Reference: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-scheduled-rule-pattern.html
    """
    ev = ctx.client("events")

    # --- refusals, each with effect-absent ------------------------------------------------
    for expression, why in [
        ("rate(1 minutes)", "a singular rate value with a plural unit"),
        ("rate(5 minute)", "a plural rate value with a singular unit"),
        ("rate(0 minutes)", "a rate value of zero"),
        ("rate(30 seconds)", "a rate unit finer than one minute"),
        ("rate(1 fortnight)", "a rate unit outside minute/hour/day"),
        ("cron(0 12 * * ?)", "a five-field cron expression -- the AWS dialect requires six"),
        ("cron(0 12 * * * *)", "a cron expression with `*` in BOTH day-of-month and day-of-week"),
    ]:
        name = ctx.unique_name("sim2real-behav-")
        code, message = _error(lambda: ev.put_rule(Name=name, ScheduleExpression=expression,
                                               State="ENABLED"))
        # ValidationException is not a modeled PutRule error, but it is what EventBridge returns.
        assert code == "ValidationException", (
            f"PutRule must reject {why} ({expression!r}): expected ValidationException, got {code}. "
            f"If the real code is InvalidEventPatternException or InvalidParameterValueException, "
            f"this assertion is the thing to correct -- see the check docstring."
        )
        assert message == "Parameter ScheduleExpression is not valid.", (
            f"PutRule must name the invalid ScheduleExpression for {expression!r}, got {message!r}"
        )
        # Effect absent: a refused PutRule must not have created a rule under that name.
        listed = [r["Name"] for r in ev.list_rules(NamePrefix=name).get("Rules", [])]
        assert listed == [], (
            f"PutRule rejected {expression!r} but ListRules(NamePrefix={name!r}) returned {listed}; "
            f"a refused create must leave no rule behind"
        )
        describe_code, describe_message = _error(lambda: ev.describe_rule(Name=name))
        assert describe_code == "ResourceNotFoundException", (
            f"PutRule rejected {expression!r} but DescribeRule({name!r}) returned {describe_code} "
            f"instead of ResourceNotFoundException"
        )
        assert describe_message == f"Rule {name} does not exist on EventBus default.", (
            f"DescribeRule({name!r}) must name the missing rule, got {describe_message!r}"
        )

    # --- positive control: the valid forms are accepted and round-trip exactly -------------
    for expression in [
        "rate(1 minute)",
        "rate(5 minutes)",
        "rate(1 hour)",
        "rate(2 days)",
        "cron(15 10 * * ? *)",          # 10:15 UTC daily, day-of-week elided with ?
        "cron(0 18 ? * MON-FRI *)",     # weekdays, day-of-month elided with ?
        "cron(0 0 1 * ? *)",            # first of every month
    ]:
        name = ctx.unique_name("sim2real-behav-")
        ev.put_rule(Name=name, ScheduleExpression=expression, State="DISABLED",
                    Description="sim2real behavioral: schedule-expression grammar",
                    Tags=[{"Key": "sim2real", "Value": CHECK}])
        ctx.on_cleanup(lambda n=name: ev.delete_rule(Name=n))
        described = ev.describe_rule(Name=name)
        assert described["ScheduleExpression"] == expression, (
            f"DescribeRule must round-trip the schedule expression byte-identically: "
            f"stored {described['ScheduleExpression']!r}, submitted {expression!r}"
        )
        # A scheduled rule carries no EventPattern, and the requested State must be honoured
        # rather than defaulted to ENABLED.
        assert "EventPattern" not in described, (
            f"a schedule-only rule must have no EventPattern, got "
            f"{described.get('EventPattern')!r}"
        )
        assert described["State"] == "DISABLED", (
            f"PutRule must honour State=DISABLED, got {described['State']!r}"
        )

    # A rule created as DISABLED must be reported as DISABLED by the list API too, not just by
    # DescribeRule -- the two read paths must agree.
    name = ctx.unique_name("sim2real-behav-")
    ev.put_rule(Name=name, ScheduleExpression="rate(1 hour)", State="DISABLED",
                Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: ev.delete_rule(Name=name))
    rules = [r for r in ev.list_rules(NamePrefix=name).get("Rules", []) if r["Name"] == name]
    assert len(rules) == 1, (
        f"expected exactly one rule named {name!r} from ListRules, got "
        f"{json.dumps([r['Name'] for r in rules])}"
    )
    assert rules[0]["State"] == "DISABLED", (
        f"ListRules reported State={rules[0]['State']!r} for a rule DescribeRule calls DISABLED"
    )
    assert rules[0]["ScheduleExpression"] == "rate(1 hour)", (
        f"ListRules reported ScheduleExpression={rules[0].get('ScheduleExpression')!r}"
    )


def _error(call) -> tuple[str, str]:
    """Run `call` and return the AWS error (code, message) it raised; raise if it succeeds."""
    try:
        call()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", "<missing Error.Code>"), err.get("Message", "")
    raise AssertionError("expected a ClientError, but the call SUCCEEDED")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
