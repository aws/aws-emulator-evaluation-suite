"""changeset-not-found-and-invalid-status-errors."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "changeset-not-found-and-invalid-status-errors"
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

def _wait_change_set_ready(cf, cs_ref, stack_ref, timeout_s=120):
    """Poll DescribeChangeSet until CREATE_COMPLETE/FAILED; return the last response.

    A just-created change set can briefly answer ChangeSetNotFound before it becomes queryable.
    """
    kwargs = {"ChangeSetName": cs_ref}
    if stack_ref is not None:
        kwargs["StackName"] = stack_ref
    deadline = time.monotonic() + timeout_s
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = cf.describe_change_set(**kwargs)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in ("ChangeSetNotFound", "ChangeSetNotFoundException"):
                time.sleep(2)
                continue
            raise
        if resp["Status"] in ("CREATE_COMPLETE", "FAILED"):
            break
        time.sleep(2)
    if resp is None:
        raise AssertionError(f"change set {cs_ref} never became visible within {timeout_s}s")
    return resp

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


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeChangeSet and GetTemplate reject a never-created change set with ChangeSetNotFound while
    DeleteChangeSet succeeds; re-executing an executed change set is InvalidChangeSetStatus with no
    effect on the change set or stack."""
    cf = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-stack-cs-")
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=stack_name))
    cf.create_stack(StackName=stack_name, TemplateBody=_sns_template())
    create_status = _wait_terminal(cf, stack_name)
    assert create_status == "CREATE_COMPLETE", (
        f"stack {stack_name} expected CREATE_COMPLETE, got {create_status!r}"
    )

    missing_cs_name = ctx.unique_name("sim2real-behav-cs-missing-")

    code, msg = _client_error(
        lambda: cf.describe_change_set(StackName=stack_name, ChangeSetName=missing_cs_name),
        "DescribeChangeSet of a never-created change set",
    )
    assert code == "ChangeSetNotFound", code
    assert msg == f"ChangeSet [{missing_cs_name}] does not exist", msg
    code, msg = _client_error(
        lambda: cf.get_template(StackName=stack_name, ChangeSetName=missing_cs_name),
        "GetTemplate of a never-created change set",
    )
    assert code == "ChangeSetNotFound", code
    assert msg == f"ChangeSet [{missing_cs_name}] does not exist", msg
    # DeleteChangeSet of a never-created change set is a no-op success, like DeleteStack.
    cf.delete_change_set(StackName=stack_name, ChangeSetName=missing_cs_name)

    cs_name = ctx.unique_name("sim2real-behav-cs-exec-")
    cs_arn = cf.create_change_set(
        StackName=stack_name,
        ChangeSetName=cs_name,
        ChangeSetType="UPDATE",
        TemplateBody=_sns_template(tags={"probe": "v2"}),
    )["Id"]
    ready = _wait_change_set_ready(cf, cs_name, stack_name)
    assert ready["Status"] == "CREATE_COMPLETE", (
        f"change set {cs_name} expected CREATE_COMPLETE, got {ready.get('Status')!r}: "
        f"{ready.get('StatusReason')!r}"
    )

    real_template = cf.get_template(StackName=stack_name, ChangeSetName=cs_name)
    body = real_template["TemplateBody"]
    parsed = json.loads(body) if isinstance(body, str) else body
    assert "Topic" in parsed.get("Resources", {}), (
        f"GetTemplate on live change set {cs_name} did not return its template: {real_template!r}"
    )

    cf.execute_change_set(StackName=stack_name, ChangeSetName=cs_name)
    exec_status = _wait_terminal(cf, stack_name)
    assert exec_status == "UPDATE_COMPLETE", (
        f"stack {stack_name} expected UPDATE_COMPLETE, got {exec_status!r}"
    )
    # An executed change set can stop resolving by (StackName, ChangeSetName) almost at once,
    # while its ARN stays describable, so read it by ARN.
    change_set_status_before = cf.describe_change_set(ChangeSetName=cs_arn)["ExecutionStatus"]
    assert change_set_status_before == "EXECUTE_COMPLETE", change_set_status_before

    code, msg = _client_error(
        lambda: cf.execute_change_set(StackName=stack_name, ChangeSetName=cs_name),
        "ExecuteChangeSet of an already-executed change set",
    )
    assert code == "InvalidChangeSetStatus", code
    assert msg == (
        f"ChangeSet [{cs_arn}] cannot be executed in its current execution status of "
        "[EXECUTE_COMPLETE]"
    ), msg

    change_set_status_after = cf.describe_change_set(ChangeSetName=cs_arn)["ExecutionStatus"]
    assert change_set_status_after == "EXECUTE_COMPLETE", (
        f"ExecutionStatus moved from EXECUTE_COMPLETE to {change_set_status_after!r} "
        "after a rejected re-execute"
    )
    final_stack_status = cf.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    assert final_stack_status == "UPDATE_COMPLETE", (
        f"stack {stack_name} moved to {final_stack_status!r} after a rejected re-execute "
        "of an already-executed change set"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
