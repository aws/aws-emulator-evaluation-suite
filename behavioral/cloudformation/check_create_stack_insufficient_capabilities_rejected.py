"""create-stack-insufficient-capabilities-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-stack-insufficient-capabilities-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]

_TEMPLATE_WITH_IAM = json.dumps(
    {
        "Resources": {
            "Role": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "lambda.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    }
                },
            }
        }
    }
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStack with an IAM resource and no capability flag returns InsufficientCapabilitiesException,
    synchronously and without creating the stack -- and the identical template with the flag supplied
    is not itself the problem: it creates cleanly, both before the omission is tried and again after.
    """
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-cfn-createcap-")
    ctx.on_cleanup(lambda: _best_effort_delete(cfn, stack_name))

    # Positive control: the same name, the same IAM-bearing template, WITH the capability
    # acknowledged -- proves the account and the template are otherwise healthy before the
    # capability flag is the only thing withheld below.
    cfn.create_stack(
        StackName=stack_name, TemplateBody=_TEMPLATE_WITH_IAM, Capabilities=["CAPABILITY_IAM"]
    )
    status = _wait_stack_status(cfn, stack_name, timeout_s=180)
    assert status == "CREATE_COMPLETE", f"positive-control create never reached CREATE_COMPLETE: {status}"

    cfn.delete_stack(StackName=stack_name)
    _wait_stack_gone(cfn, stack_name, timeout_s=180)

    # Break exactly one thing: same name, same template, capability withheld.
    code, message = _error(
        lambda: cfn.create_stack(StackName=stack_name, TemplateBody=_TEMPLATE_WITH_IAM)
    )
    assert code == "InsufficientCapabilitiesException", (
        f"expected InsufficientCapabilitiesException, got {code}"
    )
    expected = "Requires capabilities : [CAPABILITY_IAM]"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The rejection is synchronous: no stack should have been registered.
    not_found_code, not_found_message = _error(lambda: cfn.describe_stacks(StackName=stack_name))
    assert not_found_code == "ValidationError", (
        f"expected the stack to not exist after rejection, describe_stacks gave {not_found_code}"
    )
    assert not_found_message == f"Stack with id {stack_name} does not exist", (
        f"expected the exact stack-not-found message, got {not_found_message!r}"
    )

    # Restore: the identical call, capability supplied again, succeeds -- the earlier rejection
    # was specific to the missing flag, not to this name or this template.
    cfn.create_stack(
        StackName=stack_name, TemplateBody=_TEMPLATE_WITH_IAM, Capabilities=["CAPABILITY_IAM"]
    )
    restored_status = _wait_stack_status(cfn, stack_name, timeout_s=180)
    assert restored_status == "CREATE_COMPLETE", (
        f"restored create (capability supplied) never reached CREATE_COMPLETE: {restored_status}"
    )


def _error(fn):
    """Call fn(); return (code, message) of the ClientError raised. A call that
    succeeds raises AssertionError: the target accepted what AWS refuses."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _wait_stack_status(cfn, stack_name, timeout_s=180.0, interval_s=5.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as err:
            raise AssertionError(
                f"describe_stacks({stack_name}) failed while waiting for it to settle: "
                f"{err.response['Error']['Code']}"
            ) from err
        if not status.endswith("IN_PROGRESS"):
            return status
        time.sleep(interval_s)
    raise AssertionError(f"{stack_name} did not settle within {timeout_s}s, last status {status}")


def _wait_stack_gone(cfn, stack_name, timeout_s=180.0, interval_s=5.0):
    """Poll until the stack no longer resolves as an active stack by name.

    Real AWS is inconsistent about the terminal representation here -- a DescribeStacks by name can
    keep answering DELETE_COMPLETE for a while after a delete, or can flip straight to a
    ValidationError not-found. Either is "gone" for the purpose of freeing the name for reuse; this
    check is not the place that pins down which one a given account does.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as err:
            if err.response["Error"]["Code"] == "ValidationError":
                return
            raise
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise AssertionError(f"{stack_name} entered DELETE_FAILED while tearing down the positive control")
        time.sleep(interval_s)
    raise AssertionError(f"{stack_name} was not gone within {timeout_s}s")


def _best_effort_delete(cfn, stack_name):
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
