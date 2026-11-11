"""execute-changeset-rejects-non-executable-status."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-changeset-rejects-non-executable-status"
GROUP = 'change_sets'
SERVICES = ['cloudformation']


def _expect_error(fn):
    """Call fn(); return the raised ClientError. Raise if fn() succeeds unexpectedly."""
    try:
        result = fn()
    except ClientError as exc:
        return exc
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

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
        f"change set {cs_name} did not reach {targets} within {timeout_s}s (last={resp.get('Status')})"
    )

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
    """ExecuteChangeSet on a change set that never reached CREATE_COMPLETE
    (e.g. one CloudFormation marked FAILED because it contained no actual
    changes) MUST be rejected rather than silently "executed" as a no-op."""
    cf = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-behav-cs-nonexec-")
    cf.create_stack(StackName=name, TemplateBody=_sns_template(tags={"phase": "base"}))
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=name))
    _wait_stack(cf, name, {"CREATE_COMPLETE"})

    # Positive control: an executable change set with a real change must succeed. Without
    # this, "rejects a non-executable change set" is indistinguishable from "rejects every
    # ExecuteChangeSet call" -- the specific rejection this check exists to detect.
    cs_ctrl = ctx.unique_name("sim2real-behav-cs-ctrl-")
    cf.create_change_set(
        StackName=name,
        ChangeSetName=cs_ctrl,
        ChangeSetType="UPDATE",
        TemplateBody=_sns_template(tags={"phase": "base", "probe": "control"}),
    )
    ctrl_desc = _wait_changeset_status(cf, name, cs_ctrl, {"CREATE_COMPLETE", "FAILED"})
    assert ctrl_desc["Status"] == "CREATE_COMPLETE", (
        f"positive control change set did not become executable: {ctrl_desc}"
    )
    cf.execute_change_set(StackName=name, ChangeSetName=cs_ctrl)
    updated = _wait_stack(cf, name, {"UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE"})
    assert updated["StackStatus"] == "UPDATE_COMPLETE", (
        f"positive control execute_change_set did not apply: {updated}"
    )

    cs_name = ctx.unique_name("sim2real-behav-cs-nochange-")
    cs_id = cf.create_change_set(
        StackName=name,
        ChangeSetName=cs_name,
        ChangeSetType="UPDATE",
        TemplateBody=_sns_template(tags={"phase": "base", "probe": "control"}),
    )["Id"]
    desc = _wait_changeset_status(cf, name, cs_name, {"CREATE_COMPLETE", "FAILED"})
    assert desc["Status"] == "FAILED", (
        f"expected a no-op change set to land in FAILED, got {desc['Status']}"
    )
    expected_reason = (
        "The submitted information didn't contain changes. "
        "Submit different information to create a change set."
    )
    assert desc.get("StatusReason") == expected_reason, (
        f"expected StatusReason {expected_reason!r}, got {desc.get('StatusReason')!r}"
    )

    err = _expect_error(
        lambda: cf.execute_change_set(StackName=name, ChangeSetName=cs_name)
    ).response["Error"]
    assert err["Code"] == "InvalidChangeSetStatus", f"expected InvalidChangeSetStatus, got {err['Code']!r}"
    expected_message = f"ChangeSet [{cs_id}] cannot be executed in its current status of [FAILED]"
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    # The stack itself must be completely untouched by the rejected execute.
    unchanged = _describe_stack(cf, name)
    assert unchanged["StackStatus"] == "UPDATE_COMPLETE", unchanged

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
