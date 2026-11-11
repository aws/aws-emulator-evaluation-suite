"""create-changeset-missing-capabilities-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-changeset-missing-capabilities-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudformation"]

_TEMPLATE = json.dumps({
    "Resources": {
        "Role": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": {"Service": "lambda.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }],
                },
            },
        },
    },
})


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateChangeSet for an IAM-role template without CAPABILITY_IAM is refused with
    InsufficientCapabilitiesException and "Requires capabilities : [CAPABILITY_IAM]" and leaves no
    stack, while the same template with CAPABILITY_IAM yields a CREATE_COMPLETE change set."""
    cfn = ctx.client("cloudformation")

    control_stack = ctx.unique_name("sim2real-behav-cscaps-")
    control_cs = ctx.unique_name("sim2real-behav-cs-")
    ctx.on_cleanup(lambda: _cleanup_stack(cfn, control_stack))
    cfn.create_change_set(
        StackName=control_stack, ChangeSetName=control_cs, TemplateBody=_TEMPLATE,
        ChangeSetType="CREATE", Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    control_status = _wait_change_set_status(cfn, control_stack, control_cs)
    assert control_status == "CREATE_COMPLETE", (
        f"positive control: expected CreateChangeSet to succeed once CAPABILITY_IAM is "
        f"acknowledged for the same IAM-declaring template, got {control_status!r}"
    )

    stack_name = ctx.unique_name("sim2real-behav-csnocaps-")
    change_set_name = ctx.unique_name("sim2real-behav-cs-")

    code, message = _error(lambda: cfn.create_change_set(
        StackName=stack_name, ChangeSetName=change_set_name, TemplateBody=_TEMPLATE, ChangeSetType="CREATE",
    ))
    assert code == "InsufficientCapabilitiesException", f"expected InsufficientCapabilitiesException, got {code!r}"
    expected = "Requires capabilities : [CAPABILITY_IAM]"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Nothing should have been left behind: no change set, no placeholder stack.
    describe_code, describe_message = _error(lambda: cfn.describe_change_set(
        ChangeSetName=change_set_name, StackName=stack_name))
    assert describe_code == "ValidationError", (
        f"expected no change set to exist after rejection, got describe code {describe_code!r}"
    )
    expected_nf = f"Stack [{stack_name}] does not exist"
    assert describe_message == expected_nf, (
        f"expected the placeholder stack to be absent ({expected_nf!r}), got {describe_message!r}"
    )


def _error(fn):
    """Call fn(); return (code, message) of the ClientError raised. A call that
    succeeds raises AssertionError: the target accepted what AWS refuses."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _wait_change_set_status(cfn, stack_name, change_set_name, timeout_s=120, interval_s=3):
    terminal_statuses = {"CREATE_COMPLETE", "FAILED", "DELETE_COMPLETE", "DELETE_FAILED"}
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        desc = cfn.describe_change_set(StackName=stack_name, ChangeSetName=change_set_name)
        status = desc["Status"]
        if status in terminal_statuses:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"change set {change_set_name} never reached a terminal status, last={status}")


def _cleanup_stack(cfn, stack_name):
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise
    deadline = time.monotonic() + 150
    while time.monotonic() < deadline:
        try:
            stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        except ClientError as exc:
            if not (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in exc.response["Error"].get("Message", "")
            ):
                raise
            return
        if not stacks or stacks[0]["StackStatus"] == "DELETE_COMPLETE":
            return
        time.sleep(3)
    raise AssertionError(f"teardown delete of stack {stack_name} did not complete: {stacks}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
