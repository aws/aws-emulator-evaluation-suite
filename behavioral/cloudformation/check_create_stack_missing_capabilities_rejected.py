"""create-stack-missing-capabilities-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-stack-missing-capabilities-rejected"
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
    """CreateStack of an IAM-role template without CAPABILITY_IAM is refused with
    InsufficientCapabilitiesException and "Requires capabilities : [CAPABILITY_IAM]" and creates no
    stack, while the same template with CAPABILITY_IAM reaches CREATE_COMPLETE before and after."""
    cfn = ctx.client("cloudformation")
    control_stack = ctx.unique_name("sim2real-behav-capsok-")
    test_stack = ctx.unique_name("sim2real-behav-nocaps-")
    ctx.on_cleanup(lambda: _delete_stack(cfn, control_stack))
    ctx.on_cleanup(lambda: _delete_stack(cfn, test_stack))

    # Positive control: with the capability acknowledged, the exact same
    # template succeeds -- so the rejection below cannot be "this account or
    # template can never create this stack".
    cfn.create_stack(StackName=control_stack, TemplateBody=_TEMPLATE, Capabilities=["CAPABILITY_IAM"])
    control_status = _wait_stack_terminal(cfn, control_stack, timeout_s=180)
    assert control_status == "CREATE_COMPLETE", (
        f"expected the positive control (capability supplied) to reach CREATE_COMPLETE, got {control_status!r}"
    )

    # Break exactly one thing: omit the capability.
    code, message = _error(lambda: cfn.create_stack(StackName=test_stack, TemplateBody=_TEMPLATE))
    assert code == "InsufficientCapabilitiesException", f"expected InsufficientCapabilitiesException, got {code!r}"
    expected = "Requires capabilities : [CAPABILITY_IAM]"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # No stack should have been created at all -- CreateStack must reject the
    # request up front, not create a stack and then roll it back.
    describe_code, describe_message = _error(lambda: cfn.describe_stacks(StackName=test_stack))
    assert describe_code == "ValidationError", (
        f"expected no stack to exist after the rejected CreateStack, but describe_stacks gave {describe_code!r}"
    )
    assert describe_message == f"Stack with id {test_stack} does not exist", (
        f"expected the exact stack-not-found message, got {describe_message!r}"
    )

    # Restore: the identical call, now with the capability acknowledged, succeeds.
    cfn.create_stack(StackName=test_stack, TemplateBody=_TEMPLATE, Capabilities=["CAPABILITY_IAM"])
    restored_status = _wait_stack_terminal(cfn, test_stack, timeout_s=180)
    assert restored_status == "CREATE_COMPLETE", (
        f"expected the restored call (capability supplied) to reach CREATE_COMPLETE, got {restored_status!r}"
    )


def _error(fn):
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError("expected the call to raise a ClientError, but it succeeded")


def _wait_stack_terminal(cfn, stack_name, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if not status.endswith("IN_PROGRESS"):
            return status
        time.sleep(interval_s)
    raise AssertionError(
        f"stack {stack_name} did not reach a terminal status within {timeout_s}s, last seen {status!r}"
    )


def _delete_stack(cfn, stack_name):
    """Teardown: delete the stack and wait for DELETE_COMPLETE; a missing stack is fine."""
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise
        return
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
