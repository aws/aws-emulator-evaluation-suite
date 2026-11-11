"""parameter-constraint-violations-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "parameter-constraint-violations-rejected"
GROUP = 'stack_parameters'
SERVICES = ['cloudformation']

_TERMINAL_STATES = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "UPDATE_COMPLETE", "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE",
    "IMPORT_ROLLBACK_COMPLETE", "IMPORT_ROLLBACK_FAILED",
}


def _describe(cf, name):
    """DescribeStacks for one stack, or None when it no longer exists."""
    try:
        return cf.describe_stacks(StackName=name)["Stacks"][0]
    except ClientError:
        return None


def _wait_terminal(cf, name, *, timeout_s=600, interval_s=5):
    """Poll DescribeStacks until the stack reaches a terminal state; return the stack."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        stack = _describe(cf, name)
        last = None if stack is None else stack["StackStatus"]
        if stack is not None and last in _TERMINAL_STATES:
            return stack
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"stack {name} did not reach a terminal state within {timeout_s}s (last={last!r})"
            )
        time.sleep(interval_s)


def _error(fn):
    """Call fn(); return (code, message) of the ClientError raised; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


_SECRET = "sim2real-do-not-echo-9f3a"


def _template(param_name):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "Slug": {
                "Type": "String",
                "AllowedPattern": "^[a-z0-9-]+$",
                "MinLength": "3",
                "MaxLength": "20",
                "ConstraintDescription": "lowercase, digits and dashes, 3-20 chars",
            },
            "Retention": {"Type": "Number", "MinValue": "1", "MaxValue": "30"},
            "Secret": {"Type": "String", "NoEcho": True},
        },
        "Resources": {
            "Param": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {
                    "Name": param_name,
                    "Type": "String",
                    "Value": {"Fn::Sub": "${Slug}/${Retention}"},
                },
            },
        },
    })


def _params(**kwargs):
    return [{"ParameterKey": k, "ParameterValue": v} for k, v in kwargs.items()]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateStack rejects each Parameter constraint violation, a missing required value and an
    unknown key with an exact ValidationError and no stack; conforming values deploy, and a NoEcho
    value never appears in stack events.
    """
    cf = ctx.client("cloudformation")
    ssm = ctx.client("ssm")

    param_name = "/" + ctx.unique_name("sim2real-behav-pconstraint-p-")
    body = _template(param_name)

    # The declared constraints must be visible before anything is deployed.
    summary = cf.get_template_summary(TemplateBody=body)
    declared = {p["ParameterKey"]: p for p in summary.get("Parameters", [])}
    assert set(declared) == {"Slug", "Retention", "Secret"}, sorted(declared)
    assert declared["Retention"].get("ParameterType") == "Number", declared["Retention"]
    assert declared["Secret"].get("NoEcho") is True, (
        f"GetTemplateSummary must mark the NoEcho parameter, got {declared['Secret']!r}"
    )

    good = ctx.unique_name("sim2real-behav-pconstraint-ok-")
    cf.create_stack(
        StackName=good, TemplateBody=body,
        Parameters=_params(Slug="valid-slug", Retention="7", Secret=_SECRET),
    )
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=good))
    created = _wait_terminal(cf, good)
    assert created["StackStatus"] == "CREATE_COMPLETE", (
        f"conforming parameters must deploy, got {created['StackStatus']!r}: "
        f"{created.get('StackStatusReason')!r}"
    )
    good_value = ssm.get_parameter(Name=param_name)["Parameter"]["Value"]
    assert good_value == "valid-slug/7", (
        f"expected the rendered SSM value 'valid-slug/7', got {good_value!r}"
    )

    # A NoEcho value must not leak into the event stream.
    events = cf.describe_stack_events(StackName=good)["StackEvents"]
    leaked = [
        e for e in events
        if _SECRET in json.dumps({k: v for k, v in e.items() if isinstance(v, str)})
    ]
    assert not leaked, f"a NoEcho parameter value leaked into {len(leaked)} stack event(s)"

    # Each case breaks exactly one constraint.
    cases = [
        ("AllowedPattern (uppercase)", dict(Slug="Invalid-Slug", Retention="7", Secret=_SECRET),
         "Parameter Slug failed to satisfy constraint: lowercase, digits and dashes, 3-20 chars"),
        ("MinLength (2 chars)", dict(Slug="ab", Retention="7", Secret=_SECRET),
         "Parameter Slug failed to satisfy constraint: lowercase, digits and dashes, 3-20 chars"),
        ("MaxLength (21 chars)", dict(Slug="a" * 21, Retention="7", Secret=_SECRET),
         "Parameter Slug failed to satisfy constraint: lowercase, digits and dashes, 3-20 chars"),
        ("Number MinValue", dict(Slug="valid-slug", Retention="0", Secret=_SECRET),
         "Parameter 'Retention' must be a number not less than 1"),
        ("Number MaxValue", dict(Slug="valid-slug", Retention="99", Secret=_SECRET),
         "Parameter 'Retention' must be a number not greater than 30"),
        ("Number typing", dict(Slug="valid-slug", Retention="not-a-number", Secret=_SECRET),
         "Parameter 'Retention' must be a number."),
    ]
    for label, kwargs, expected in cases:
        bad = ctx.unique_name("sim2real-behav-pconstraint-bad-")
        code, message = _error(
            lambda name=bad, kw=kwargs: cf.create_stack(
                StackName=name, TemplateBody=body, Parameters=_params(**kw),
            )
        )
        assert code == "ValidationError", (
            f"{label} must be rejected with ValidationError, got {code!r} ({message!r})"
        )
        assert message == expected, f"{label}: expected message {expected!r}, got {message!r}"
        assert _describe(cf, bad) is None, (
            f"{label} was rejected but left a stack behind: {bad}"
        )

    # A required parameter with no Default must be supplied.
    missing = ctx.unique_name("sim2real-behav-pconstraint-missing-")
    code, message = _error(lambda: cf.create_stack(
        StackName=missing, TemplateBody=body,
        Parameters=_params(Slug="valid-slug", Retention="7"),
    ))
    assert code == "ValidationError", (
        f"a missing required parameter must be rejected, got {code!r}"
    )
    expected_missing = "Parameters: [Secret] must have values"
    assert message == expected_missing, (
        f"the rejection must name the missing parameter: expected {expected_missing!r}, got {message!r}"
    )
    assert _describe(cf, missing) is None, missing

    # A ParameterKey the template does not declare must be rejected, not ignored.
    unknown = ctx.unique_name("sim2real-behav-pconstraint-unknown-")
    code, message = _error(lambda: cf.create_stack(
        StackName=unknown, TemplateBody=body,
        Parameters=_params(Slug="valid-slug", Retention="7", Secret=_SECRET, Bogus="x"),
    ))
    assert code == "ValidationError", (
        f"an undeclared ParameterKey must be rejected, got {code!r}"
    )
    expected_unknown = "Parameters: [Bogus] do not exist in the template"
    assert message == expected_unknown, (
        f"the rejection must name the undeclared parameter: expected {expected_unknown!r}, got {message!r}"
    )
    assert _describe(cf, unknown) is None, unknown

    # Control: the originally valid stack is untouched by all of the above.
    still = _describe(cf, good)
    assert still is not None and still["StackStatus"] == "CREATE_COMPLETE", still
    final_value = ssm.get_parameter(Name=param_name)["Parameter"]["Value"]
    assert final_value == "valid-slug/7", (
        f"good stack's SSM value must survive all rejected calls unchanged, got {final_value!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
