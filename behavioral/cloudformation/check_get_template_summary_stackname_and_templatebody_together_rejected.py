"""get-template-summary-stackname-and-templatebody-together-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-template-summary-stackname-and-templatebody-together-rejected"
GROUP = "negative-classes"
SERVICES = ["cloudformation"]

_CREATE_TERMINAL = ("CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetTemplateSummary refuses StackName together with TemplateBody with the exact
    mutually-exclusive-parameter message, while each one supplied alone succeeds.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_GetTemplateSummary.html
    """
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-cfngts-")
    template = _parameter_template()

    cfn.create_stack(StackName=stack_name, TemplateBody=template)
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_name))
    status = _wait_terminal(cfn, stack_name)
    assert status == "CREATE_COMPLETE", f"the stack under test did not reach CREATE_COMPLETE: {status!r}"

    # Positive controls: each parameter alone succeeds.
    by_name = cfn.get_template_summary(StackName=stack_name)
    assert by_name["ResourceTypes"] == ["AWS::SSM::Parameter"], (
        f"GetTemplateSummary(StackName=...) reported {by_name['ResourceTypes']!r}, "
        f"expected ['AWS::SSM::Parameter']"
    )
    by_body = cfn.get_template_summary(TemplateBody=template)
    assert by_body["ResourceTypes"] == ["AWS::SSM::Parameter"], (
        f"GetTemplateSummary(TemplateBody=...) reported {by_body['ResourceTypes']!r}, "
        f"expected ['AWS::SSM::Parameter']"
    )

    error = _client_error(lambda: cfn.get_template_summary(StackName=stack_name, TemplateBody=template))
    assert error.get("Code") == "ValidationError", (
        f"StackName and TemplateBody together must raise ValidationError, got {error!r}"
    )
    assert error.get("Message") == "Exactly one of Template URL, Template Body, Stack Name must be specified.", (
        f"expected the mutually-exclusive-parameter message, got {error!r}"
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
