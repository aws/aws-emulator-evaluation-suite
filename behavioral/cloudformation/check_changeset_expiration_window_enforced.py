"""changeset-expiration-window-enforced."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "changeset-expiration-window-enforced"
GROUP = 'change_sets'
SERVICES = ['cloudformation']


def _client_error(fn, what):
    """Return (code, message) of the ClientError `fn` raises; raise AssertionError if it succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected {what} to be rejected, but the call succeeded")


def _wait_stack_status(cf, name, targets, timeout_s=180, interval_s=3):
    """Poll DescribeStacks until StackStatus is in targets; return the stack dict."""
    target = {targets} if isinstance(targets, str) else set(targets)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = cf.describe_stacks(StackName=name)["Stacks"][0]
        except ClientError:
            last = None
        if last is not None and last.get("StackStatus") in target:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"stack {name} did not reach {target} (last={last.get('StackStatus') if last else None!r})"
    )

def _wait_changeset_status(cf, stack_name, cs_name, targets, timeout_s=120, interval_s=2):
    """Poll DescribeChangeSet until Status is in targets; return the response."""
    target = {targets} if isinstance(targets, str) else set(targets)
    deadline = time.monotonic() + timeout_s
    resp = cf.describe_change_set(StackName=stack_name, ChangeSetName=cs_name)
    while time.monotonic() < deadline:
        resp = cf.describe_change_set(StackName=stack_name, ChangeSetName=cs_name)
        if resp.get("Status") in target:
            return resp
        time.sleep(interval_s)
    raise AssertionError(
        f"change set {cs_name} on {stack_name} did not reach {target} within {timeout_s}s "
        f"(last status={resp.get('Status')!r})"
    )

def _sns_template(tags=None):
    props = {}
    if tags:
        props["Tags"] = [{"Key": k, "Value": v} for k, v in tags.items()]
    return json.dumps({
        "Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": props}},
        "Outputs": {"TopicArn": {"Value": {"Ref": "Topic"}}},
    })


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Executing one change set of a stack removes its other AVAILABLE change set: DescribeChangeSet
    and ExecuteChangeSet of that sibling are both refused with ChangeSetNotFound and
    "ChangeSet [<name>] does not exist", so it can never be applied later."""
    cf = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-behav-cs-exp-")
    cf.create_stack(StackName=name, TemplateBody=_sns_template(tags={"phase": "base"}))
    ctx.on_cleanup(lambda: _delete_stack(cf, name))
    _wait_stack_status(cf, name, {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE"})

    cs_stale = ctx.unique_name("sim2real-behav-cs-stale-")
    cs_winner = ctx.unique_name("sim2real-behav-cs-winner-")

    cf.create_change_set(
        StackName=name,
        ChangeSetName=cs_stale,
        TemplateBody=_sns_template(tags={"phase": "stale-candidate"}),
        ChangeSetType="UPDATE",
    )
    described_stale = _wait_changeset_status(cf, name, cs_stale, {"CREATE_COMPLETE", "FAILED"})
    assert described_stale["Status"] == "CREATE_COMPLETE", described_stale.get("StatusReason")
    assert described_stale["ExecutionStatus"] == "AVAILABLE", described_stale

    cf.create_change_set(
        StackName=name,
        ChangeSetName=cs_winner,
        TemplateBody=_sns_template(tags={"phase": "winner"}),
        ChangeSetType="UPDATE",
    )
    described_winner = _wait_changeset_status(cf, name, cs_winner, {"CREATE_COMPLETE", "FAILED"})
    assert described_winner["Status"] == "CREATE_COMPLETE", described_winner.get("StatusReason")

    cf.execute_change_set(StackName=name, ChangeSetName=cs_winner)
    _wait_stack_status(cf, name, {"UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE"})

    # Executing one change set removes every other change set of the stack, so the sibling is
    # gone rather than merely marked non-AVAILABLE.
    err, err_msg = _client_error(
        lambda: cf.describe_change_set(StackName=name, ChangeSetName=cs_stale),
        "DescribeChangeSet of the sibling of an executed change set",
    )
    assert err == "ChangeSetNotFound", err
    assert err_msg == f"ChangeSet [{cs_stale}] does not exist", err_msg

    # Overly-permissive boundary: executing the now-stale change set must be
    # rejected, never silently (re-)applied.
    code, msg = _client_error(
        lambda: cf.execute_change_set(StackName=name, ChangeSetName=cs_stale),
        "ExecuteChangeSet of the stale change set",
    )
    assert code == "ChangeSetNotFound", (
        f"expected the stale change set's execution to be rejected, got {code}"
    )
    assert msg == f"ChangeSet [{cs_stale}] does not exist", msg


def _delete_stack(cf, name):
    """Teardown: delete the stack and wait for DELETE_COMPLETE; a failed delete raises."""
    cf.delete_stack(StackName=name)
    cf.get_waiter("stack_delete_complete").wait(
        StackName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
