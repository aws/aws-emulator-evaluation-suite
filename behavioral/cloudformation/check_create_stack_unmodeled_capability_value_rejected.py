"""create-stack-unmodeled-capability-value-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-stack-unmodeled-capability-value-rejected"
GROUP = "negative-classes"
SERVICES = ["cloudformation"]

_CREATE_TERMINAL = ("CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED")

#: The order CloudFormation's own enum-constraint message lists it in, confirmed against a live
#: ValidationError, not the model's declaration order.
_CAPABILITY_ENUM = "CAPABILITY_AUTO_EXPAND, CAPABILITY_NAMED_IAM, CAPABILITY_IAM"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStack with a Capabilities entry outside the three modeled values fails ValidationError
    with the exact enum-constraint message, the stack is never created, and the identical template
    with no Capabilities argument reaches CREATE_COMPLETE.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_CreateStack.html
    """
    cfn = ctx.client("cloudformation")
    template = _parameter_template()

    good_name = ctx.unique_name("sim2real-behav-cfncap-ok-")
    cfn.create_stack(StackName=good_name, TemplateBody=template)
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=good_name))
    status = _wait_terminal(cfn, good_name)
    assert status == "CREATE_COMPLETE", (
        f"the positive control (same template, no Capabilities) did not reach CREATE_COMPLETE: {status!r}"
    )

    bad_name = ctx.unique_name("sim2real-behav-cfncap-bad-")
    error = _client_error(lambda: cfn.create_stack(
        StackName=bad_name, TemplateBody=template, Capabilities=["CAPABILITY_BOGUS"],
    ))
    assert error.get("Code") == "ValidationError", (
        f"an unmodeled Capabilities value must raise ValidationError, got {error!r}"
    )
    assert error.get("Message") == (
        "1 validation error detected: Value '[CAPABILITY_BOGUS]' at 'capabilities' failed to "
        f"satisfy constraint: Member must satisfy constraint: [Member must satisfy enum value "
        f"set: [{_CAPABILITY_ENUM}]]"
    ), f"expected the Capabilities enum-constraint message, got {error!r}"

    describe_error = _client_error(lambda: cfn.describe_stacks(StackName=bad_name))
    assert describe_error.get("Code") == "ValidationError", (
        f"expected no stack under the rejected name, got {describe_error!r}"
    )
    assert describe_error.get("Message") == f"Stack with id {bad_name} does not exist", (
        f"expected 'Stack with id {bad_name} does not exist', got {describe_error!r}"
    )


def _wait_terminal(cfn, name, timeout_s=180):
    deadline = time.monotonic() + timeout_s
    last = "UNKNOWN"
    while time.monotonic() < deadline:
        try:
            last = cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
        except ClientError:
            last = "UNKNOWN"
        if last in _CREATE_TERMINAL:
            return last
        time.sleep(2)
    raise AssertionError(f"stack {name!r} did not reach a terminal state within {timeout_s}s (last={last!r})")


def _client_error(fn):
    """Call fn(); return the botocore Error dict if a ClientError is raised. An unexpected
    success raises, so a target that accepts input AWS refuses fails as an acceptance rather
    than as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _parameter_template() -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Param": {"Type": "AWS::SSM::Parameter", "Properties": {"Type": "String", "Value": "sim2real"}}
            },
        }
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
