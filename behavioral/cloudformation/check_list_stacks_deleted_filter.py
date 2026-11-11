"""list-stacks-deleted-filter."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-stacks-deleted-filter"
GROUP = 'stack_lifecycle'
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

def _handle_template():
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}},
    })


def _find_by_name(cf, name, status_filter):
    paginator = cf.get_paginator("list_stacks")
    for page in paginator.paginate(StackStatusFilter=list(status_filter)):
        for summary in page.get("StackSummaries", []):
            if summary["StackName"] == name:
                return summary
    return None


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Deleted stacks appear in ListStacks with DELETE_COMPLETE filter, and stop appearing
    under the status filter they held while alive — proving the filter genuinely selects on
    current status rather than returning every stack regardless of what was asked."""
    cf = ctx.client("cloudformation")
    name = _create_and_wait(ctx, cf, _handle_template())

    alive = _find_by_name(cf, name, ["CREATE_COMPLETE"])
    assert alive is not None, f"Stack {name} not in ListStacks(CREATE_COMPLETE) while alive"

    cf.delete_stack(StackName=name)
    _wait_deleted(cf, name)

    still_under_create = _find_by_name(cf, name, ["CREATE_COMPLETE"])
    assert still_under_create is None, (
        f"Deleted stack {name} still in ListStacks(CREATE_COMPLETE): {still_under_create!r}"
    )

    deleted = _find_by_name(cf, name, ["DELETE_COMPLETE"])
    assert deleted is not None, f"Deleted stack {name} not in ListStacks(DELETE_COMPLETE)"
    assert deleted["StackStatus"] == "DELETE_COMPLETE", (
        f"Expected StackStatus DELETE_COMPLETE for {name}, got {deleted['StackStatus']!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
