"""execute-change-set."""
from __future__ import annotations

import json
import time
import uuid
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-change-set"
GROUP = 'change_sets'
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


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """ExecuteChangeSet applies changes and the added resource is independently
    observable via ListStackResources, not just the stack's own status word."""
    cf = ctx.client("cloudformation")
    stack_name = _create_and_wait(ctx, cf, _handle_template())
    cs_name = f"cs-{uuid.uuid4().hex[:8]}"
    cf.create_change_set(
        StackName=stack_name,
        ChangeSetName=cs_name,
        TemplateBody=_two_handles_template(),
    )
    ctx.on_cleanup(lambda: cf.delete_change_set(ChangeSetName=cs_name, StackName=stack_name))
    deadline = time.monotonic() + 60
    resp = cf.describe_change_set(ChangeSetName=cs_name, StackName=stack_name)
    while time.monotonic() < deadline:
        resp = cf.describe_change_set(ChangeSetName=cs_name, StackName=stack_name)
        if resp["Status"] in ("CREATE_COMPLETE", "FAILED"):
            break
        time.sleep(2)
    assert resp["Status"] == "CREATE_COMPLETE", (
        f"change set {cs_name} did not become executable: "
        f"status={resp['Status']!r} reason={resp.get('StatusReason')!r}"
    )
    cf.execute_change_set(ChangeSetName=cs_name, StackName=stack_name)
    status = _wait_terminal(cf, stack_name)
    assert status == "UPDATE_COMPLETE", f"Expected UPDATE_COMPLETE, got {status}"

    resources = cf.list_stack_resources(StackName=stack_name)["StackResourceSummaries"]
    by_logical_id = {r["LogicalResourceId"]: r for r in resources}
    added = by_logical_id.get("Handle2")
    assert added is not None, (
        f"Handle2 not found via an independent ListStackResources read; "
        f"stack has {sorted(by_logical_id)}"
    )
    assert added["ResourceStatus"] == "CREATE_COMPLETE", (
        f"Handle2 resource status {added['ResourceStatus']!r}, expected CREATE_COMPLETE"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
