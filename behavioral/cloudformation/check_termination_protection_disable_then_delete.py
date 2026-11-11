"""termination-protection-disable-then-delete."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "termination-protection-disable-then-delete"
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

def _wait_deleted(cf, name, timeout_s=180):
    """Wait until the stack reaches DELETE_COMPLETE or vanishes from DescribeStacks."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status = cf.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
            if status == "DELETE_COMPLETE":
                return
            if status == "DELETE_FAILED":
                raise AssertionError(f"Stack {name} reached DELETE_FAILED")
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ValidationError":
                return
            raise
        time.sleep(2)
    raise AssertionError(f"Stack {name} not deleted within {timeout_s}s")

def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) if a ClientError is raised.
    Raises on unexpected success."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError("expected the call to be rejected, but it succeeded")

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


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteStack on a termination-protected stack is rejected and the stack is left
    untouched; disabling protection then lets the identical DeleteStack call succeed,
    and the deleted stack's id is unusable afterward."""
    cf = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-behav-stk-")
    created = cf.create_stack(
        StackName=name,
        TemplateBody=_handle_template(),
        EnableTerminationProtection=True,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    stack_id = created["StackId"]
    ctx.on_cleanup(lambda: _delete_protected(cf, name))
    _wait_terminal(cf, name)

    # positive control: protection is on, confirmed by an independent read
    described = cf.describe_stacks(StackName=name)["Stacks"][0]
    assert described["EnableTerminationProtection"] is True, (
        f"expected EnableTerminationProtection True after create, got {described.get('EnableTerminationProtection')!r}"
    )

    # break: delete while protected is rejected with the specific error
    error = _error(lambda: cf.delete_stack(StackName=name))
    expected = (
        "ValidationError",
        f"Stack [{name}] cannot be deleted while TerminationProtection is enabled",
    )
    assert error == expected, f"expected {expected!r} deleting a protected stack, got {error!r}"

    # effect absent: independent read shows the stack untouched and still protected
    still_there = cf.describe_stacks(StackName=name)["Stacks"][0]
    assert still_there["StackId"] == stack_id, "stack id changed after a supposedly-blocked delete"
    assert still_there["StackStatus"] == "CREATE_COMPLETE", (
        f"stack should be untouched by the blocked delete, got {still_there['StackStatus']}"
    )
    assert still_there["EnableTerminationProtection"] is True, (
        "EnableTerminationProtection flipped False after a delete that should have been blocked"
    )

    # restore: disable protection, confirmed by an independent read
    cf.update_termination_protection(StackName=name, EnableTerminationProtection=False)
    disabled = cf.describe_stacks(StackName=name)["Stacks"][0]
    assert disabled["EnableTerminationProtection"] is False, (
        "EnableTerminationProtection still True after UpdateTerminationProtection(False)"
    )

    # the identical delete call now succeeds
    cf.delete_stack(StackName=name)
    _wait_deleted(cf, name)

    # gone and unusable: a mutation on the now-dead stack name also fails
    gone = _error(lambda: cf.update_termination_protection(StackName=name, EnableTerminationProtection=True))
    expected_gone = ("ValidationError", f"Stack [{name}] does not exist")
    assert gone == expected_gone, f"expected {expected_gone!r} mutating a deleted stack, got {gone!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
