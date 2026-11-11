"""parameter-allowed-values-reject."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "parameter-allowed-values-reject"
GROUP = 'stack_parameters'
SERVICES = ['cloudformation']


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) if a ClientError is raised, else raise."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _describe(cf, name):
    """DescribeStacks for one stack, or None once it no longer exists."""
    try:
        return cf.describe_stacks(StackName=name)["Stacks"][0]
    except ClientError:
        return None


def _wait_terminal(cf, name, *, timeout_s=120, interval_s=3):
    """Poll DescribeStacks until the stack reaches a terminal state; return the stack."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        stack = _describe(cf, name)
        last = None if stack is None else stack["StackStatus"]
        if stack is not None and last in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE"}:
            return stack
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"stack {name} did not reach a terminal state within {timeout_s}s (last={last!r})"
            )
        time.sleep(interval_s)


def _parameters_template(*, default=None, allowed_values=None, no_echo=False):
    param = {"Type": "String", "Description": "Queue suffix"}
    if default is not None:
        param["Default"] = default
    if allowed_values:
        param["AllowedValues"] = allowed_values
    if no_echo:
        param["NoEcho"] = True
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"Suffix": param},
        "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}},
        "Outputs": {"ParamValue": {"Value": {"Ref": "Suffix"}}},
    })


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Creating a stack with a parameter value not in AllowedValues raises ValidationError and
    leaves no stack behind, while the identical template with an allowed value deploys fine."""
    cf = ctx.client("cloudformation")
    body = _parameters_template(allowed_values=["alpha", "beta"])

    # Positive control: an allowed value must actually deploy.
    good = ctx.unique_name("sim2real-behav-stk-ok-")
    cf.create_stack(
        StackName=good,
        TemplateBody=body,
        Parameters=[{"ParameterKey": "Suffix", "ParameterValue": "alpha"}],
    )
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=good))
    created = _wait_terminal(cf, good)
    assert created["StackStatus"] == "CREATE_COMPLETE", (
        f"an allowed value must deploy, got {created['StackStatus']!r}: "
        f"{created.get('StackStatusReason')!r}"
    )

    # Negative: a value outside AllowedValues must be rejected outright.
    bad = ctx.unique_name("sim2real-behav-stk-bad-")
    code, message = _error(
        lambda: cf.create_stack(
            StackName=bad,
            TemplateBody=body,
            Parameters=[{"ParameterKey": "Suffix", "ParameterValue": "gamma"}],
        )
    )
    assert code == "ValidationError", f"Expected ValidationError, got {code!r}"
    expected = "Parameter 'Suffix' must be one of AllowedValues"
    assert message == expected, f"expected refusal message {expected!r}, got {message!r}"

    # Effect must be absent: the rejected call must never have created a stack.
    assert _describe(cf, bad) is None, f"rejected CreateStack left a stack behind: {bad}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
