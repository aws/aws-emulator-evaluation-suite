"""describe-shows-termination-protection."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-shows-termination-protection"
GROUP = 'termination_protection'
SERVICES = ['cloudformation']


_TERMINAL_STATES = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "UPDATE_COMPLETE", "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE",
    "IMPORT_ROLLBACK_COMPLETE", "IMPORT_ROLLBACK_FAILED",
}

def _wait_terminal(cf, name, timeout_s=180):
    """Poll DescribeStacks until the stack reaches a terminal state; return it."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = cf.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
        except ClientError:
            last = "UNKNOWN"
        if last in _TERMINAL_STATES:
            return last
        time.sleep(2)
    raise AssertionError(f"stack {name} terminal not met within {timeout_s}s (last={last!r})")

def _delete_protected(cf, name):
    """Teardown for a termination-protected stack: disable protection, then delete."""
    try:
        cf.update_termination_protection(StackName=name, EnableTerminationProtection=False)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise
    try:
        cf.delete_stack(StackName=name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise

def _handle_template():
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}},
    })


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeStacks reports EnableTerminationProtection status, both when it is
    enabled at creation and when it is left at its default -- a target that
    hardcodes either value fails the other stack."""
    cf = ctx.client("cloudformation")
    protected_name = ctx.unique_name("sim2real-behav-stk-")
    plain_name = ctx.unique_name("sim2real-behav-stk-")
    cf.create_stack(
        StackName=protected_name, TemplateBody=_handle_template(), EnableTerminationProtection=True
    )
    ctx.on_cleanup(lambda: _delete_protected(cf, protected_name))
    cf.create_stack(StackName=plain_name, TemplateBody=_handle_template())
    ctx.on_cleanup(lambda: _delete_protected(cf, plain_name))
    _wait_terminal(cf, protected_name)
    _wait_terminal(cf, plain_name)

    protected = cf.describe_stacks(StackName=protected_name)["Stacks"][0]
    assert protected.get("EnableTerminationProtection") is True, (
        f"expected EnableTerminationProtection=True for {protected_name}, "
        f"got {protected.get('EnableTerminationProtection')!r}"
    )

    plain = cf.describe_stacks(StackName=plain_name)["Stacks"][0]
    assert plain.get("EnableTerminationProtection") is False, (
        f"expected EnableTerminationProtection=False for {plain_name} (default), "
        f"got {plain.get('EnableTerminationProtection')!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
