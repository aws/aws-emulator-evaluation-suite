"""rollback-complete-stack-cannot-be-updated."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rollback-complete-stack-cannot-be-updated"
GROUP = 'overly-permissive'
SERVICES = ['cloudformation']


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Overly-permissive check: a stack in ROLLBACK_COMPLETE is only deletable — UpdateStack
    must be rejected."""
    cfn = ctx.client("cloudformation")

    # Positive control: the identical operation succeeds on a healthy stack, so the rejection
    # below is provably about ROLLBACK_COMPLETE and not a universally-broken UpdateStack.
    control_name = ctx.unique_name("sim2real-behav-cfn-rbc-control-")
    cfn.create_stack(
        StackName=control_name,
        TemplateBody=_sns_topic_template(ctx.unique_name("sim2real-behav-cfn-topic-a-")),
    )
    ctx.on_cleanup(lambda: _delete_stack_quiet(cfn, control_name))
    control_created = _wait_stack_status(cfn, control_name, timeout_s=180)
    assert control_created["StackStatus"] == "CREATE_COMPLETE", (
        f"positive-control stack expected CREATE_COMPLETE, got {control_created['StackStatus']}"
    )

    cfn.update_stack(
        StackName=control_name,
        TemplateBody=_sns_topic_template(
            ctx.unique_name("sim2real-behav-cfn-topic-a-"), display_name="rbc-positive-control"
        ),
    )
    control_updated = _wait_stack_status(cfn, control_name, timeout_s=180)
    assert control_updated["StackStatus"] == "UPDATE_COMPLETE", (
        f"positive-control UpdateStack expected UPDATE_COMPLETE, got {control_updated['StackStatus']}"
    )

    # Negative: the same operation, aimed at a stack stuck in ROLLBACK_COMPLETE, is rejected.
    name = ctx.unique_name("sim2real-behav-cfn-rbc-noupd-")
    tmpl = _wait_condition_template(timeout_s=10)
    cfn.create_stack(StackName=name, TemplateBody=tmpl)
    ctx.on_cleanup(lambda: _delete_stack_quiet(cfn, name))
    final = _wait_stack_status(cfn, name, timeout_s=300)
    assert final["StackStatus"] == "ROLLBACK_COMPLETE", final["StackStatus"]

    good_tmpl = _sns_topic_template(ctx.unique_name("sim2real-behav-cfn-topic-b-"))
    code, message = _error(lambda: cfn.update_stack(StackName=name, TemplateBody=good_tmpl))
    assert code == "ValidationError", f"expected ValidationError, got {code!r}"
    expected = f"Stack:{final['StackId']} is in ROLLBACK_COMPLETE state and can not be updated."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # still in ROLLBACK_COMPLETE, and deleting it is allowed
    final_status = _describe_stack(cfn, name)["StackStatus"]
    assert final_status == "ROLLBACK_COMPLETE", (
        f"expected stack to remain ROLLBACK_COMPLETE after rejected update, got {final_status}"
    )


_TERMINAL_STACK_STATUSES = {
    "CREATE_COMPLETE",
    "CREATE_FAILED",
    "ROLLBACK_COMPLETE",
    "ROLLBACK_FAILED",
    "UPDATE_COMPLETE",
    "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_ROLLBACK_FAILED",
    "DELETE_COMPLETE",
    "DELETE_FAILED",
}


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    success raises, so an emulator accepting what AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


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


def _wait_condition_template(timeout_s=10) -> str:
    """A stack whose only resource is a WaitCondition that times out unless signalled."""
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "MyHandle": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
                "MyWait": {
                    "Type": "AWS::CloudFormation::WaitCondition",
                    "DependsOn": "MyHandle",
                    "Properties": {
                        "Handle": {"Ref": "MyHandle"},
                        "Timeout": str(timeout_s),
                        "Count": 1,
                    },
                },
            },
        }
    )


def _describe_stack(cfn, name):
    stacks = cfn.describe_stacks(StackName=name).get("Stacks", [])
    assert stacks, f"stack {name} not found"
    return stacks[0]


def _wait_stack_status(cfn, name, timeout_s=180, interval_s=3):
    """Poll DescribeStacks until the stack reaches any terminal status."""
    return _poll_until(
        lambda: _describe_stack(cfn, name),
        lambda stack: stack.get("StackStatus") in _TERMINAL_STACK_STATUSES,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"stack {name} reaching a terminal status",
    )


def _delete_stack_quiet(cfn, name):
    try:
        cfn.delete_stack(StackName=name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
