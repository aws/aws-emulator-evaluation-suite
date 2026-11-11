"""enable-nonexistent-rule-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "enable-nonexistent-rule-fails"
GROUP = 'rule'
SERVICES = ['events']


def _error(fn):
    """(code, message) of a call that must fail; a call that succeeds raises AssertionError."""
    try:
        fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError("expected a ClientError, but the call succeeded")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """EnableRule on a name that was never put_rule'd fails with ResourceNotFoundException,
    the absence holds under an independent read, and creating that same name afterward makes
    the identical call succeed."""
    ev = ctx.client("events")

    # Positive control: EnableRule succeeds against a rule that really exists, so a later
    # refusal cannot be "every EnableRule call fails here" wearing a not-found costume.
    control = ctx.unique_name("sim2real-behav-rule-control-")
    ev.put_rule(Name=control, EventPattern='{"source": ["sim2real.behav"]}')
    ctx.on_cleanup(lambda: ev.delete_rule(Name=control))
    ev.enable_rule(Name=control)
    state = ev.describe_rule(Name=control)["State"]
    assert state == "ENABLED", f"expected control rule ENABLED after EnableRule, got {state}"

    # Break exactly one thing: reference a rule name that was never created.
    absent = ctx.unique_name("sim2real-behav-rule-absent-")
    not_found = ("ResourceNotFoundException", f"Rule {absent} does not exist on EventBus default.")
    err = _error(lambda: ev.enable_rule(Name=absent))
    assert err == not_found, f"expected {not_found!r}, got {err!r}"

    # Effect absent, via an independent read (DescribeRule, not EnableRule again).
    describe_err = _error(lambda: ev.describe_rule(Name=absent))
    assert describe_err == not_found, (
        f"expected DescribeRule to also report {not_found!r} for the never-created "
        f"rule, got {describe_err!r}"
    )

    # Restore: creating the same name now makes the identical call succeed.
    ev.put_rule(Name=absent, EventPattern='{"source": ["sim2real.behav"]}')
    ctx.on_cleanup(lambda: ev.delete_rule(Name=absent))
    ev.enable_rule(Name=absent)
    restored_state = ev.describe_rule(Name=absent)["State"]
    assert restored_state == "ENABLED", (
        f"expected {absent} ENABLED after EnableRule once the rule exists, got {restored_state}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
