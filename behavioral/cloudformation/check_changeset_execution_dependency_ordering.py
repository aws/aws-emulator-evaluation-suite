"""changeset-execution-dependency-ordering."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "changeset-execution-dependency-ordering"
GROUP = 'change_sets'
SERVICES = ['cloudformation']


def _describe_stack(cf, name):
    stacks = cf.describe_stacks(StackName=name).get("Stacks", [])
    return stacks[0] if stacks else None

def _wait_stack(cf, name, targets, timeout_s=180):
    """Poll DescribeStacks until StackStatus is in `targets`; return the stack dict."""
    deadline = time.monotonic() + timeout_s
    stack = None
    while time.monotonic() < deadline:
        try:
            stack = _describe_stack(cf, name)
        except ClientError:
            stack = None
        if stack is not None and stack.get("StackStatus") in targets:
            return stack
        time.sleep(3)
    raise AssertionError(f"stack {name} did not reach {targets} within {timeout_s}s (last={stack})")

def _wait_changeset_status(cf, stack_name, cs_name, targets, timeout_s=120):
    deadline = time.monotonic() + timeout_s
    resp = cf.describe_change_set(StackName=stack_name, ChangeSetName=cs_name)
    while time.monotonic() < deadline:
        resp = cf.describe_change_set(StackName=stack_name, ChangeSetName=cs_name)
        if resp.get("Status") in targets:
            return resp
        time.sleep(2)
    raise AssertionError(
        f"change set {cs_name!r} did not reach {sorted(targets)} within {timeout_s}s "
        f"(last status {resp.get('Status')!r})"
    )

def _client_error(fn, what):
    """Return (code, message) of the ClientError `fn` raises; raise AssertionError if it succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected {what} to be rejected, but the call succeeded")

def _dependency_chain_template():
    """Three SNS topics with an explicit DependsOn chain (A -> B) plus an
    implicit Ref dependency (C references B's ARN in a Tag, and also explicitly
    DependsOn B) -- forcing the deployment order A, B, C."""
    return json.dumps(
        {
            "Resources": {
                "TopicA": {"Type": "AWS::SNS::Topic", "Properties": {}},
                "TopicB": {"Type": "AWS::SNS::Topic", "DependsOn": "TopicA", "Properties": {}},
                "TopicC": {
                    "Type": "AWS::SNS::Topic",
                    "DependsOn": "TopicB",
                    "Properties": {"Tags": [{"Key": "ref-to-b", "Value": {"Ref": "TopicB"}}]},
                },
            }
        }
    )

def _dependency_chain_template_bad_dependson():
    """Same shape but TopicB DependsOn a logical id that doesn't exist."""
    return json.dumps(
        {
            "Resources": {
                "TopicA": {"Type": "AWS::SNS::Topic", "Properties": {}},
                "TopicB": {
                    "Type": "AWS::SNS::Topic",
                    "DependsOn": "GhostResourceThatDoesNotExist",
                    "Properties": {},
                },
            }
        }
    )


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A change set with a DependsOn chain plus a Ref dependency completes its topics in order
    (A before B before C), and CreateChangeSet refuses a DependsOn on a nonexistent logical id
    with ValidationError and its exact message rather than ignoring it."""
    cf = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-behav-cs-order-")
    cs = ctx.unique_name("sim2real-behav-cs-")
    cf.create_change_set(
        StackName=name,
        ChangeSetName=cs,
        ChangeSetType="CREATE",
        TemplateBody=_dependency_chain_template(),
    )
    ctx.on_cleanup(lambda: _delete_stack(cf, name))

    desc = _wait_changeset_status(cf, name, cs, {"CREATE_COMPLETE", "FAILED"})
    assert desc["Status"] == "CREATE_COMPLETE", desc.get("StatusReason")

    changes_by_id = {
        c["ResourceChange"]["LogicalResourceId"]: c["ResourceChange"] for c in desc["Changes"]
    }
    assert set(changes_by_id) == {"TopicA", "TopicB", "TopicC"}
    assert all(c["Action"] == "Add" for c in changes_by_id.values())

    cf.execute_change_set(StackName=name, ChangeSetName=cs)
    stack = _wait_stack(cf, name, {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE"})
    assert stack["StackStatus"] == "CREATE_COMPLETE", stack.get("StackStatusReason")

    events = cf.describe_stack_events(StackName=name)["StackEvents"]
    # StackEvents come back newest-first; reverse to chronological order.
    chronological = list(reversed(events))
    complete_time = {}
    for e in chronological:
        if e["LogicalResourceId"] in {"TopicA", "TopicB", "TopicC"} and e["ResourceStatus"] == "CREATE_COMPLETE":
            complete_time.setdefault(e["LogicalResourceId"], e["Timestamp"])

    assert set(complete_time) == {"TopicA", "TopicB", "TopicC"}, complete_time
    assert complete_time["TopicA"] <= complete_time["TopicB"] <= complete_time["TopicC"], (
        "resources must complete in DependsOn/Ref dependency order",
        complete_time,
    )

    # Overly-permissive boundary: DependsOn referencing a logical id that
    # doesn't exist anywhere in the template must be rejected at
    # CreateChangeSet time, not accepted and silently dropped.
    bad_name = ctx.unique_name("sim2real-behav-cs-order-bad-")
    bad_cs = ctx.unique_name("sim2real-behav-cs-bad-")
    ctx.on_cleanup(lambda: _delete_stack(cf, bad_name))
    code, msg = _client_error(
        lambda: cf.create_change_set(
            StackName=bad_name,
            ChangeSetName=bad_cs,
            ChangeSetType="CREATE",
            TemplateBody=_dependency_chain_template_bad_dependson(),
        ),
        "CreateChangeSet with a DependsOn on a nonexistent logical id",
    )
    assert code == "ValidationError", f"expected ValidationError, got {code}"
    assert msg == (
        "Template format error: Unresolved resource dependencies "
        "[GhostResourceThatDoesNotExist] in the Resources block of the template"
    ), msg


def _delete_stack(cf, name):
    """Teardown: delete the stack and wait for DELETE_COMPLETE; a failed delete raises."""
    cf.delete_stack(StackName=name)
    cf.get_waiter("stack_delete_complete").wait(
        StackName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
