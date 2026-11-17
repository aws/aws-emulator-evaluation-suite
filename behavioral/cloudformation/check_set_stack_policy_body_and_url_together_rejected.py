"""set-stack-policy-body-and-url-together-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-stack-policy-body-and-url-together-rejected"
GROUP = "negative-classes"
SERVICES = ["cloudformation"]

_CREATE_TERMINAL = ("CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SetStackPolicy refuses StackPolicyBody together with StackPolicyURL with the exact
    mutually-exclusive-parameter message, and leaves the stack's existing policy unchanged while
    the identical StackPolicyBody supplied alone is accepted and read back.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_SetStackPolicy.html
    """
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-cfnspb-")
    template = _parameter_template()

    cfn.create_stack(StackName=stack_name, TemplateBody=template)
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_name))
    status = _wait_terminal(cfn, stack_name)
    assert status == "CREATE_COMPLETE", f"the stack under test did not reach CREATE_COMPLETE: {status!r}"

    allow_policy = {
        "Statement": [{"Effect": "Allow", "Action": "Update:*", "Principal": "*", "Resource": "*"}]
    }
    cfn.set_stack_policy(StackName=stack_name, StackPolicyBody=json.dumps(allow_policy))
    live = json.loads(cfn.get_stack_policy(StackName=stack_name)["StackPolicyBody"])
    assert live == allow_policy, f"the control policy did not read back: {live!r}"

    deny_policy = {
        "Statement": [{"Effect": "Deny", "Action": "Update:*", "Principal": "*", "Resource": "*"}]
    }
    error = _client_error(lambda: cfn.set_stack_policy(
        StackName=stack_name,
        StackPolicyBody=json.dumps(deny_policy),
        StackPolicyURL="https://s3.amazonaws.com/does-not-matter/policy.json",
    ))
    assert error.get("Code") == "ValidationError", (
        f"StackPolicyBody and StackPolicyURL together must raise ValidationError, got {error!r}"
    )
    assert error.get("Message") == "You cannot specify both StackPolicyURL and StackPolicyBody", (
        f"expected the mutually-exclusive-parameter message, got {error!r}"
    )

    still_live = json.loads(cfn.get_stack_policy(StackName=stack_name)["StackPolicyBody"])
    assert still_live == allow_policy, (
        f"the rejected call must leave the stack policy unchanged; got {still_live!r}"
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
