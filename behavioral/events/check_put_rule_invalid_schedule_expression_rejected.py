"""put-rule-invalid-schedule-expression-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-rule-invalid-schedule-expression-rejected"
GROUP = 'rule'
SERVICES = ['events']

def _client_error(call):
    """Botocore Error dict of a call that must fail; an unexpected success raises."""
    try:
        call()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError("expected a ClientError, but the call SUCCEEDED")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutRule with ScheduleExpression "rate(0 minutes)" is rejected with ValidationException and
    creates no rule, while "rate(5 minutes)" is accepted and round-trips as a positive control."""
    ev = ctx.client("events")

    # Positive control: a syntactically valid ScheduleExpression is accepted and round-trips,
    # so the account/credentials are otherwise healthy for this call.
    good_name = ctx.unique_name("sim2real-behav-rule-")
    ev.put_rule(Name=good_name, ScheduleExpression="rate(5 minutes)",
                Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: ev.delete_rule(Name=good_name))
    described = ev.describe_rule(Name=good_name)
    assert described["ScheduleExpression"] == "rate(5 minutes)", (
        f"positive control: expected ScheduleExpression 'rate(5 minutes)', got "
        f"{described.get('ScheduleExpression')!r}"
    )

    bad_name = ctx.unique_name("sim2real-behav-rule-")
    err = _client_error(lambda: ev.put_rule(Name=bad_name, ScheduleExpression="rate(0 minutes)"))
    assert err.get("Code") == "ValidationException", (
        f"PutRule with ScheduleExpression='rate(0 minutes)' must fail with ValidationException, "
        f"got {err}"
    )
    assert err.get("Message") == "Parameter ScheduleExpression is not valid.", (
        f"expected message 'Parameter ScheduleExpression is not valid.', got {err.get('Message')!r}"
    )

    listed = [r["Name"] for r in ev.list_rules(NamePrefix=bad_name).get("Rules", [])]
    assert listed == [], (
        f"PutRule rejected 'rate(0 minutes)' but ListRules(NamePrefix={bad_name!r}) returned "
        f"{listed}; a refused create must leave no rule behind"
    )

    err2 = _client_error(lambda: ev.describe_rule(Name=bad_name))
    assert err2.get("Code") == "ResourceNotFoundException", (
        f"rejected PutRule must not create a rule, describe gave {err2}"
    )
    expected_message = f"Rule {bad_name} does not exist on EventBus default."
    assert err2.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err2.get('Message')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
