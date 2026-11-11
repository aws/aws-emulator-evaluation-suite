"""execute-failed-changeset-rejected."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-failed-changeset-rejected"
GROUP = 'change_sets'
SERVICES = ['cloudformation']


def _expect_error(fn):
    """Call fn(); return the raised ClientError. Raise if fn() succeeds unexpectedly."""
    try:
        result = fn()
    except ClientError as exc:
        return exc
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

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
    return resp

def _topic_template(topic_name=None, extra_tag=None):
    props = {}
    if topic_name:
        props["TopicName"] = topic_name
    if extra_tag:
        props["Tags"] = [{"Key": "probe", "Value": extra_tag}]
    return json.dumps({
        "Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": props}},
        "Outputs": {"TopicArn": {"Value": {"Ref": "Topic"}}},
    })


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A change set with no changes ends FAILED with the "didn't contain changes" StatusReason, and
    ExecuteChangeSet on it fails with InvalidChangeSetStatus and its exact message, leaving the stack
    UPDATE_COMPLETE; a change set with a real diff executes."""
    cf = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-behav-cs-failed-")
    cf.create_stack(StackName=name, TemplateBody=_topic_template(extra_tag="base"))
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=name))
    _wait_stack_status(cf, name, {"CREATE_COMPLETE"})

    # Positive control: a change set with a real diff reaches CREATE_COMPLETE and
    # executing it actually updates the stack.
    cs_ok = ctx.unique_name("sim2real-behav-cs-ok-")
    cf.create_change_set(
        StackName=name,
        ChangeSetName=cs_ok,
        ChangeSetType="UPDATE",
        TemplateBody=_topic_template(extra_tag="updated"),
    )
    desc_ok = _wait_changeset_status(cf, name, cs_ok, {"CREATE_COMPLETE", "FAILED"})
    assert desc_ok["Status"] == "CREATE_COMPLETE", desc_ok
    cf.execute_change_set(StackName=name, ChangeSetName=cs_ok)
    after_update = _wait_stack_status(cf, name, {"UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE"})
    assert after_update["StackStatus"] == "UPDATE_COMPLETE", after_update

    # The negative subject: a change set identical to the now-current template has
    # nothing to apply, so CloudFormation marks it FAILED rather than CREATE_COMPLETE.
    cs = ctx.unique_name("sim2real-behav-cs-")
    cs_id = cf.create_change_set(
        StackName=name,
        ChangeSetName=cs,
        ChangeSetType="UPDATE",
        TemplateBody=_topic_template(extra_tag="updated"),
    )["Id"]
    desc = _wait_changeset_status(cf, name, cs, {"CREATE_COMPLETE", "FAILED"})
    assert desc["Status"] == "FAILED", desc
    expected_reason = (
        "The submitted information didn't contain changes. "
        "Submit different information to create a change set."
    )
    assert desc.get("StatusReason") == expected_reason, (
        f"expected StatusReason {expected_reason!r}, got {desc.get('StatusReason')!r}"
    )

    err = _expect_error(lambda: cf.execute_change_set(StackName=name, ChangeSetName=cs)).response["Error"]
    assert err["Code"] == "InvalidChangeSetStatus", err["Code"]
    expected_message = f"ChangeSet [{cs_id}] cannot be executed in its current status of [FAILED]"
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    # Independent read: the rejected execute must leave the stack exactly where the
    # positive control left it, not advance it into any update.
    unchanged = cf.describe_stacks(StackName=name)["Stacks"][0]
    assert unchanged["StackStatus"] == "UPDATE_COMPLETE", unchanged

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
