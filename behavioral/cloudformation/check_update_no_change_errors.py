"""update-no-change-errors."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-no-change-errors"
GROUP = 'stack_update'
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

def _create_and_wait(ctx, cf, template, *, parameters=None, tags=None, capabilities=None):
    """CreateStack (registered for teardown) and wait for CREATE_COMPLETE; return the name."""
    name = ctx.unique_name("sim2real-behav-stk-")
    kwargs = {"StackName": name, "TemplateBody": template}
    if parameters:
        kwargs["Parameters"] = parameters
    if tags:
        kwargs["Tags"] = tags
    if capabilities:
        kwargs["Capabilities"] = capabilities
    cf.create_stack(**kwargs)
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=name))
    status = _wait_terminal(cf, name)
    if status != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {status}, expected CREATE_COMPLETE")
    return name

def _client_error(fn):
    """Call fn(); return the ClientError it raises. A success is a defect and RAISES."""
    try:
        result = fn()
    except ClientError as exc:
        return exc
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")

def _handle_template():
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}},
    })

def _two_handles_template():
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Handle1": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
            "Handle2": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
        },
    })

def _resource_ids(cf, name):
    return sorted(
        r["LogicalResourceId"]
        for r in cf.list_stack_resources(StackName=name)["StackResourceSummaries"]
    )


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateStack with an identical template fails with ValidationError "No updates are to be performed."
    and leaves the stack UPDATE_COMPLETE with the same resources, while an UpdateStack that adds a
    resource reaches UPDATE_COMPLETE."""
    cf = ctx.client("cloudformation")
    name = _create_and_wait(ctx, cf, _handle_template())

    # --- Positive control: a real change must be accepted and applied.
    cf.update_stack(StackName=name, TemplateBody=_two_handles_template())
    status = _wait_terminal(cf, name)
    assert status == "UPDATE_COMPLETE", f"positive control: expected UPDATE_COMPLETE, got {status!r}"
    baseline_ids = _resource_ids(cf, name)
    assert baseline_ids == ["Handle1", "Handle2"], (
        f"positive control: expected both resources provisioned, got {baseline_ids}"
    )

    # --- Break exactly one thing: the identical shape of call, with no actual change.
    error = _client_error(
        lambda: cf.update_stack(StackName=name, TemplateBody=_two_handles_template())
    )
    err = error.response.get("Error", {})
    code = err.get("Code")
    message = err.get("Message", "")
    assert code == "ValidationError", f"Expected ValidationError, got {code!r}: {message!r}"
    # The code alone is shared with every other UpdateStack rejection (wrong state, bad
    # template, missing capability, ...) -- the message is what actually proves this is the
    # no-op case rather than any of those.
    assert message == "No updates are to be performed.", (
        f'expected the no-op message "No updates are to be performed.", got {message!r}'
    )

    # --- Effect absent: the rejected no-op update must not have touched the stack.
    still = cf.describe_stacks(StackName=name)["Stacks"][0]
    assert still["StackStatus"] == "UPDATE_COMPLETE", (
        f"a rejected no-op update must leave the stack status unchanged, got {still['StackStatus']!r}"
    )
    assert _resource_ids(cf, name) == baseline_ids, (
        f"a rejected no-op update must not change the resource set, got {_resource_ids(cf, name)}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
