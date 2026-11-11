"""update-nonexistent-stack-not-found."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-nonexistent-stack-not-found"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]

_TERMINAL_CREATE = {
    "CREATE_COMPLETE",
    "CREATE_FAILED",
    "ROLLBACK_COMPLETE",
    "ROLLBACK_FAILED",
}
_TERMINAL_UPDATE = {
    "UPDATE_COMPLETE",
    "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_ROLLBACK_FAILED",
}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateStack against a never-created stack name fails with ValidationError and the exact
    message "Stack [<name>] does not exist", while the identical call against an existing stack
    reaches UPDATE_COMPLETE (positive control)."""
    cfn = ctx.client("cloudformation")

    # --- Positive control: create a real stack, then update it. Both must succeed before the
    #     negative below means anything.
    real_name = ctx.unique_name("sim2real-behav-cfn-real-")
    topic = ctx.unique_name("sim2real-behav-cfn-topic-")
    cfn.create_stack(StackName=real_name, TemplateBody=_sns_topic_template(topic))
    ctx.on_cleanup(lambda: _delete_stack_quiet(cfn, real_name))
    created = _wait_stack_status(cfn, real_name, _TERMINAL_CREATE, timeout_s=180)
    assert created["StackStatus"] == "CREATE_COMPLETE", (
        f"positive control: expected the setup stack to reach CREATE_COMPLETE, "
        f"got {created['StackStatus']}"
    )

    cfn.update_stack(
        StackName=real_name,
        TemplateBody=_sns_topic_template(topic, display_name="control"),
    )
    updated = _wait_stack_status(cfn, real_name, _TERMINAL_UPDATE, timeout_s=180)
    assert updated["StackStatus"] == "UPDATE_COMPLETE", (
        f"positive control: UpdateStack against an existing stack must succeed, "
        f"got {updated['StackStatus']}"
    )

    # --- Break exactly one thing: the identical shape of call, against a stack name that has
    #     never been created.
    missing_name = ctx.unique_name("sim2real-behav-cfn-missing-")
    missing_tmpl = _sns_topic_template(ctx.unique_name("sim2real-behav-cfn-topic-upd-"))
    error = _client_error(
        lambda: cfn.update_stack(StackName=missing_name, TemplateBody=missing_tmpl)
    )
    err = error.response.get("Error", {})
    code = err.get("Code")
    message = err.get("Message", "")
    assert code == "ValidationError", (
        f"expected ValidationError, got {code!r}: {message}"
    )
    # The code alone is shared with every other UpdateStack rejection (wrong state, bad
    # template, missing capability, ...) -- the message is what actually proves this is the
    # not-found case rather than any of those.
    expected = f"Stack [{missing_name}] does not exist"
    assert message == expected, (
        f"expected the stack-not-found message naming {missing_name!r}: {expected!r}, got {message!r}"
    )


def _client_error(fn):
    """Call fn(); return the ClientError it raises. A success is a defect and RAISES."""
    try:
        result = fn()
    except ClientError as exc:
        return exc
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _delete_stack_quiet(cfn, name):
    try:
        cfn.delete_stack(StackName=name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise


def _wait_stack_status(cfn, name, terminal_statuses, *, timeout_s=180, interval_s=3):
    """Poll DescribeStacks until the stack reaches any status in terminal_statuses."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        stacks = cfn.describe_stacks(StackName=name).get("Stacks", [])
        assert stacks, f"stack {name} not found while waiting for a terminal status"
        last = stacks[0]
        if last.get("StackStatus") in terminal_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"stack {name} did not reach a terminal status within {timeout_s}s; last={last!r}"
    )


def _sns_topic_template(topic_name, display_name=None) -> str:
    props = {"TopicName": topic_name}
    if display_name is not None:
        props["DisplayName"] = display_name
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {"MyTopic": {"Type": "AWS::SNS::Topic", "Properties": props}},
            "Outputs": {"TopicArnOutput": {"Value": {"Ref": "MyTopic"}}},
        }
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
