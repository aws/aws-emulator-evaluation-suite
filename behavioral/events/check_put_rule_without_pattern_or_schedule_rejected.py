"""put-rule-without-pattern-or-schedule-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-rule-without-pattern-or-schedule-rejected"
GROUP = 'rule'
SERVICES = ['events']

def _client_error(fn):
    """Botocore Error dict of a call that must fail; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutRule with neither EventPattern nor ScheduleExpression is rejected with ValidationException
    and creates no rule, while a PutRule with an EventPattern succeeds as a positive control."""
    ev = ctx.client("events")

    control_name = ctx.unique_name("sim2real-behav-rule-ctl-")
    control = ev.put_rule(
        Name=control_name,
        EventPattern=json.dumps({"source": ["sim2real.control"]}),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda n=control_name: ev.delete_rule(Name=n))
    assert control.get("RuleArn"), "positive control: PutRule with a real EventPattern must succeed"

    name = ctx.unique_name("sim2real-behav-rule-")
    err = _client_error(lambda: ev.put_rule(Name=name))
    code = err.get("Code")
    assert code == "ValidationException", (
        f"PutRule with no EventPattern and no ScheduleExpression must fail with "
        f"ValidationException, got {code!r} ({err.get('Message')!r})"
    )
    expected_message = "Parameter(s) EventPattern or ScheduleExpression must be specified."
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    err2 = _client_error(lambda: ev.describe_rule(Name=name))
    code2 = err2.get("Code")
    assert code2 == "ResourceNotFoundException", (
        f"rejected PutRule must not create a rule, describe gave {code2!r}"
    )
    expected_describe_message = f"Rule {name} does not exist on EventBus default."
    assert err2.get("Message") == expected_describe_message, (
        f"expected message {expected_describe_message!r}, got {err2.get('Message')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
