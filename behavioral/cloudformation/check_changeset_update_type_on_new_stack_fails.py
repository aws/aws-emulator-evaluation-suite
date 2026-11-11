"""changeset-update-type-on-new-stack-fails."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "changeset-update-type-on-new-stack-fails"
GROUP = 'overly-permissive'
SERVICES = ['cloudformation']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateChangeSet with ChangeSetType UPDATE for a never-existing stack is refused with
    ValidationError and "Stack [<name>] does not exist" and creates no stack, while a CREATE change
    set for a new stack reaches CREATE_COMPLETE."""
    cfn = ctx.client("cloudformation")
    control_name = ctx.unique_name("sim2real-behav-cfn-cs-badtype-control-")
    control_cs = ctx.unique_name("sim2real-behav-cs-control-")
    bad_name = ctx.unique_name("sim2real-behav-cfn-cs-badtype-")
    bad_cs = ctx.unique_name("sim2real-behav-cs-badtype-")
    tmpl = _sns_topic_template(ctx.unique_name("sim2real-behav-cfn-topic-"))

    # Positive control: CreateChangeSet(ChangeSetType=CREATE) against a genuinely new stack
    # must succeed.
    control_resp = cfn.create_change_set(
        StackName=control_name,
        ChangeSetName=control_cs,
        TemplateBody=tmpl,
        ChangeSetType="CREATE",
    )
    ctx.on_cleanup(lambda: _delete_stack_quiet(cfn, control_name))
    control_cs_arn = control_resp["Id"]
    assert control_cs_arn.startswith("arn:"), control_resp
    control_status = _poll_until(
        lambda: cfn.describe_change_set(ChangeSetName=control_cs_arn),
        lambda r: r.get("Status") in {"CREATE_COMPLETE", "FAILED"},
        timeout_s=120,
        interval_s=3,
        description="control change set reaching a terminal status",
    )
    assert control_status["Status"] == "CREATE_COMPLETE", (
        control_status["Status"],
        control_status.get("StatusReason"),
    )

    code, msg = _client_error(
        lambda: cfn.create_change_set(
            StackName=bad_name,
            ChangeSetName=bad_cs,
            TemplateBody=tmpl,
            ChangeSetType="UPDATE",
        ),
        "CreateChangeSet(UPDATE) on a nonexistent stack",
    )
    assert code == "ValidationError", code
    assert msg == f"Stack [{bad_name}] does not exist", msg

    # Effect-absent, via an independent read at a different operation: the rejected UPDATE
    # attempt must not have materialized a stack under that name.
    describe_code, describe_msg = _client_error(
        lambda: cfn.describe_stacks(StackName=bad_name),
        "DescribeStacks of the never-created stack",
    )
    assert describe_code == "ValidationError", (
        f"expected DescribeStacks({bad_name}) to report no such stack after the rejected "
        f"UPDATE change set, got {describe_code!r}"
    )
    assert describe_msg == f"Stack with id {bad_name} does not exist", describe_msg


def _client_error(fn, what):
    """Return (code, message) of the ClientError `fn` raises; raise AssertionError if it succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected {what} to be rejected, but the call succeeded")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _delete_stack_quiet(cfn, name):
    """Teardown: delete the stack and wait for DELETE_COMPLETE; a missing stack is fine."""
    try:
        cfn.delete_stack(StackName=name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise
        return
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
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
