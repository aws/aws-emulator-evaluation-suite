"""missing-capability-iam-error."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "missing-capability-iam-error"
GROUP = 'errors'
SERVICES = ['cloudformation']


def _error(fn):
    """Call fn(); return botocore (Error.Code, Error.Message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _template_with_named_role(role_name):
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Role": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "RoleName": role_name,
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "lambda.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                    },
                }
            },
        }
    )


def _best_effort_delete_stack(cf, stack_name):
    try:
        cf.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_create_settled(ctx, cf, stack_name, cap_s):
    """Poll DescribeStacks until the stack leaves CREATE_IN_PROGRESS; return its status."""
    timeout_s = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cf.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if status != "CREATE_IN_PROGRESS":
            return status
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"stack {stack_name} settling: the run budget ended first; not graded")
    raise AssertionError(f"stack {stack_name} still {status!r} {timeout_s}s after CreateStack")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStack with a named IAM resource and no capability flag is rejected up front, with no
    stack registered; the identical call with CAPABILITY_NAMED_IAM supplied then succeeds."""
    cf = ctx.client("cloudformation")

    # Break exactly one thing: the identical shape of stack, minus the capability flag.
    stack_name = ctx.unique_name("sim2real-behav-stk-")
    role_name = ctx.unique_name("sim2real-behav-role-")
    template = _template_with_named_role(role_name)
    ctx.on_cleanup(lambda: _best_effort_delete_stack(cf, stack_name))

    code, message = _error(
        lambda: cf.create_stack(StackName=stack_name, TemplateBody=template)
    )
    assert code == "InsufficientCapabilitiesException", (
        f"Expected InsufficientCapabilitiesException, got {code!r}"
    )
    assert message == "Requires capabilities : [CAPABILITY_NAMED_IAM]", (
        f"unexpected InsufficientCapabilitiesException message {message!r}"
    )

    # Effect absent: the rejection is synchronous -- no stack was registered under that name.
    describe_code, describe_message = _error(lambda: cf.describe_stacks(StackName=stack_name))
    assert describe_code == "ValidationError", (
        f"expected no stack to exist after the rejected CreateStack, describe_stacks gave {describe_code!r}"
    )
    assert describe_message == f"Stack with id {stack_name} does not exist", (
        f"unexpected ValidationError message {describe_message!r}"
    )

    # Positive control, ordered after the rejection: the identical call with the capability
    # supplied succeeds, so the account creates such stacks and only the missing flag was refused.
    cf.create_stack(
        StackName=stack_name,
        TemplateBody=template,
        Capabilities=["CAPABILITY_NAMED_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    restored_status = _wait_create_settled(ctx, cf, stack_name, 600)
    assert restored_status == "CREATE_COMPLETE", (
        f"expected the identical call to succeed once CAPABILITY_NAMED_IAM is supplied, got {restored_status!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
