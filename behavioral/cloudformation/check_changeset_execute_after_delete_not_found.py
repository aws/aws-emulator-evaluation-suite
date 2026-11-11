"""changeset-execute-after-delete-not-found."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "changeset-execute-after-delete-not-found"
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

def _wait_changeset_status(cf, stack_name, cs_name, targets, timeout_s=120):
    deadline = time.monotonic() + timeout_s
    resp = cf.describe_change_set(StackName=stack_name, ChangeSetName=cs_name)
    while time.monotonic() < deadline:
        resp = cf.describe_change_set(StackName=stack_name, ChangeSetName=cs_name)
        if resp.get("Status") in targets:
            return resp
        time.sleep(2)
    raise AssertionError(
        f"change set {cs_name} on {stack_name} did not reach {sorted(targets)} "
        f"within {timeout_s}s (last status={resp.get('Status')!r})"
    )

def _client_error(fn, what):
    """Return (code, message) of the ClientError `fn` raises; raise AssertionError if it succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected {what} to be rejected, but the call succeeded")


def _sns_template(tags=None):
    props = {}
    if tags:
        props["Tags"] = [{"Key": k, "Value": v} for k, v in tags.items()]
    return json.dumps(
        {
            "Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": props}},
            "Outputs": {"TopicArn": {"Value": {"Ref": "Topic"}}},
        }
    )


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After DeleteChangeSet, DescribeChangeSet and ExecuteChangeSet of its name are refused with
    ChangeSetNotFound and "ChangeSet [<name>] does not exist", and the freed name can be reused
    for a change set with a new ChangeSetId."""
    cf = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-behav-stack-cs-gone-")
    cf.create_stack(StackName=name, TemplateBody=_sns_template())
    ctx.on_cleanup(lambda: _delete_stack(cf, name))
    _wait_terminal(cf, name)

    cs_name = ctx.unique_name("sim2real-behav-cs-gone-")
    created = cf.create_change_set(
        StackName=name,
        ChangeSetName=cs_name,
        ChangeSetType="UPDATE",
        TemplateBody=_sns_template(tags={"v": "2"}),
    )
    _wait_changeset_status(cf, name, cs_name, {"CREATE_COMPLETE", "FAILED"})
    cf.delete_change_set(StackName=name, ChangeSetName=cs_name)

    code, msg = _client_error(
        lambda: cf.describe_change_set(StackName=name, ChangeSetName=cs_name),
        "DescribeChangeSet of the deleted change set",
    )
    assert code == "ChangeSetNotFound", code
    assert msg == f"ChangeSet [{cs_name}] does not exist", msg
    code, msg = _client_error(
        lambda: cf.execute_change_set(StackName=name, ChangeSetName=cs_name),
        "ExecuteChangeSet of the deleted change set",
    )
    assert code == "ChangeSetNotFound", code
    assert msg == f"ChangeSet [{cs_name}] does not exist", msg

    # The freed name is reusable, and the change set it now names is a fresh
    # identity, not the deleted one silently reappearing.
    recreated = cf.create_change_set(
        StackName=name,
        ChangeSetName=cs_name,
        ChangeSetType="UPDATE",
        TemplateBody=_sns_template(tags={"v": "3"}),
    )
    _wait_changeset_status(cf, name, cs_name, {"CREATE_COMPLETE", "FAILED"})
    assert recreated["Id"] != created["Id"], (
        f"reusing freed name {cs_name!r} produced ChangeSetId {recreated['Id']!r}, "
        f"identical to the deleted change set {created['Id']!r} -- looks resurrected"
    )


def _delete_stack(cf, name):
    """Teardown: delete the stack and wait for DELETE_COMPLETE; a failed delete raises."""
    cf.delete_stack(StackName=name)
    cf.get_waiter("stack_delete_complete").wait(
        StackName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
