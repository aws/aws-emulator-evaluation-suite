"""duplicate-stack-name-error."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "duplicate-stack-name-error"
GROUP = 'errors'
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
    status = None
    while time.monotonic() < deadline:
        try:
            status = cf.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
            if status == "DELETE_COMPLETE":
                return
            if status == "DELETE_FAILED":
                raise AssertionError(f"Stack {name} reached DELETE_FAILED")
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ValidationError":
                return
            raise
        time.sleep(2)
    raise AssertionError(f"Stack {name} not deleted within {timeout_s}s (last={status!r})")

def _create_and_wait(ctx, cf, template, *, parameters=None, tags=None, capabilities=None):
    """CreateStack (registered for teardown) and wait for CREATE_COMPLETE; return the name."""
    name = ctx.unique_name("sim2real-behav-stk-")
    kwargs = {"StackName": name, "TemplateBody": template, "Tags": tags or [{"Key": "owner", "Value": "fidelity"}]}
    if parameters:
        kwargs["Parameters"] = parameters
    if capabilities:
        kwargs["Capabilities"] = capabilities
    cf.create_stack(**kwargs)
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=name))
    status = _wait_terminal(cf, name)
    if status != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {status}, expected CREATE_COMPLETE")
    return name

def _expect_error(fn):
    """Call fn(); return the raised ClientError. Raise if fn() succeeds unexpectedly."""
    try:
        result = fn()
    except ClientError as exc:
        return exc
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")

def _handle_template():
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}},
    })


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Creating a stack with a name that already has a live stack raises AlreadyExistsException,
    leaves the original stack and its resources untouched, and frees the name for reuse once that
    original stack is deleted."""
    cf = ctx.client("cloudformation")
    name = _create_and_wait(ctx, cf, _handle_template())
    original_stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]

    err = _expect_error(
        lambda: cf.create_stack(StackName=name, TemplateBody=_handle_template())
    ).response["Error"]
    assert err["Code"] == "AlreadyExistsException", f"Expected AlreadyExistsException, got {err['Code']!r}"
    expected_message = f"Stack [{name}] already exists"
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    # effect absent: an independent read shows exactly the original stack, unchanged
    stacks = cf.describe_stacks(StackName=name)["Stacks"]
    assert len(stacks) == 1, f"expected exactly one stack named {name!r}, got {len(stacks)}"
    assert stacks[0]["StackId"] == original_stack_id, "rejected duplicate must not spawn a second StackId"
    assert stacks[0]["StackStatus"] == "CREATE_COMPLETE", stacks[0]["StackStatus"]
    resources = cf.describe_stack_resources(StackName=name)["StackResources"]
    handle_resources = [r for r in resources if r["LogicalResourceId"] == "Handle"]
    assert len(handle_resources) == 1, f"expected exactly one Handle resource, got {len(handle_resources)}"

    # restore: delete the original, which is what was forbidding the name
    cf.delete_stack(StackName=name)
    _wait_deleted(cf, name)

    # identical call now succeeds: the name is reusable once the conflict is gone
    cf.create_stack(StackName=name, TemplateBody=_handle_template(), Tags=[{"Key": "owner", "Value": "fidelity"}])
    recreate_status = _wait_terminal(cf, name)
    assert recreate_status == "CREATE_COMPLETE", f"recreated stack did not reach CREATE_COMPLETE (got {recreate_status!r})"
    new_stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
    assert new_stack_id != original_stack_id, "recreated stack must get a fresh StackId, not the deleted one's"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
