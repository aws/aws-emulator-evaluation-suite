"""list-change-sets."""
from __future__ import annotations

import json
import time
import uuid
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-change-sets"
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


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListChangeSets includes the change set we created, with the status
    the list endpoint reports matching the change set's own terminal status."""
    cf = ctx.client("cloudformation")
    stack_name = _create_and_wait(
        ctx, cf, _handle_template(),
        tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    cs_name = f"cs-{uuid.uuid4().hex[:8]}"
    cf.create_change_set(
        StackName=stack_name,
        ChangeSetName=cs_name,
        TemplateBody=_two_handles_template(),
    )
    ctx.on_cleanup(lambda: cf.delete_change_set(ChangeSetName=cs_name, StackName=stack_name))
    deadline = time.monotonic() + 60
    status = None
    while time.monotonic() < deadline:
        status = cf.describe_change_set(ChangeSetName=cs_name, StackName=stack_name)["Status"]
        if status in ("CREATE_COMPLETE", "FAILED"):
            break
        time.sleep(2)
    assert status == "CREATE_COMPLETE", (
        f"change set {cs_name} ended in {status!r} (or never reached a terminal "
        "status within 60s), expected CREATE_COMPLETE"
    )

    list_resp = cf.list_change_sets(StackName=stack_name)
    summaries = list_resp.get("Summaries", [])
    matching = [cs for cs in summaries if cs["ChangeSetName"] == cs_name]
    names = [cs["ChangeSetName"] for cs in summaries]
    assert len(matching) == 1, f"expected exactly one ChangeSet named {cs_name} in ListChangeSets, got {names}"
    assert matching[0]["Status"] == "CREATE_COMPLETE", (
        f"ListChangeSets reported status {matching[0]['Status']!r} for {cs_name}, expected CREATE_COMPLETE"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
