"""create-stack-rollback-monitoring-time-exceeds-maximum-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-stack-rollback-monitoring-time-exceeds-maximum-rejected"
GROUP = "negative-classes"
SERVICES = ["cloudformation"]

_CREATE_TERMINAL = ("CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStack with RollbackConfiguration.MonitoringTimeInMinutes above its 180-minute maximum
    fails ValidationError with the exact range-constraint message, the stack is never created, and
    the identical template with a valid monitoring time reaches CREATE_COMPLETE.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_RollbackConfiguration.html
    """
    cfn = ctx.client("cloudformation")
    template = _parameter_template()

    # MonitoringTimeInMinutes=0: a valid value that does not hold CREATE_IN_PROGRESS open for a
    # real monitoring period, unlike any value above 0.
    good_name = ctx.unique_name("sim2real-behav-cfnrbk-ok-")
    cfn.create_stack(
        StackName=good_name, TemplateBody=template,
        RollbackConfiguration={"RollbackTriggers": [], "MonitoringTimeInMinutes": 0},
    )
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=good_name))
    status = _wait_terminal(cfn, good_name)
    assert status == "CREATE_COMPLETE", (
        f"the positive control (MonitoringTimeInMinutes=0, a valid value) did not reach "
        f"CREATE_COMPLETE: {status!r}"
    )
    live = cfn.describe_stacks(StackName=good_name)["Stacks"][0]
    assert live["RollbackConfiguration"]["MonitoringTimeInMinutes"] == 0, (
        f"the control stack echoes MonitoringTimeInMinutes "
        f"{live['RollbackConfiguration']['MonitoringTimeInMinutes']!r}, expected 0"
    )

    bad_name = ctx.unique_name("sim2real-behav-cfnrbk-bad-")
    error = _client_error(lambda: cfn.create_stack(
        StackName=bad_name, TemplateBody=template,
        RollbackConfiguration={"RollbackTriggers": [], "MonitoringTimeInMinutes": 181},
    ))
    assert error.get("Code") == "ValidationError", (
        f"MonitoringTimeInMinutes=181 (above the 180 maximum) must raise ValidationError, got {error!r}"
    )
    assert error.get("Message") == (
        "1 validation error detected: Value '181' at "
        "'rollbackConfiguration.monitoringTimeInMinutes' failed to satisfy constraint: Member must "
        "have value less than or equal to 180"
    ), f"expected the MonitoringTimeInMinutes range-constraint message, got {error!r}"

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
