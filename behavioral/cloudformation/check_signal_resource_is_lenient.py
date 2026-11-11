"""signal-resource-is-lenient."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "signal-resource-is-lenient"
GROUP = 'signal'
SERVICES = ['cloudformation']


@tags("axis:happy-path", "cap:c3", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """SignalResource is strikingly permissive on real CloudFormation: signals aimed at a
    non-signalable resource AND at a logical id that isn't in the template are both accepted
    (no error) and are inert — the stack keeps its terminal status."""
    cfn = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-behav-cfn-signal-len-")
    tmpl = _sns_topic_template(ctx.unique_name("sim2real-behav-cfn-topic-"))
    cfn.create_stack(
        StackName=name,
        TemplateBody=tmpl,
        Tags=[{"Key": "owner", "Value": "fidelity"}],
    )
    ctx.on_cleanup(lambda: _delete_stack_quiet(cfn, name))
    _wait_stack_status(cfn, name)

    _must_succeed(
        lambda: cfn.signal_resource(
            StackName=name,
            LogicalResourceId="MyTopic",
            UniqueId=ctx.unique_name("sig-"),
            Status="SUCCESS",
        ),
        "SignalResource on a non-signalable resource",
    )

    _must_succeed(
        lambda: cfn.signal_resource(
            StackName=name,
            LogicalResourceId="NoSuchLogicalResource",
            UniqueId=ctx.unique_name("sig-"),
            Status="SUCCESS",
        ),
        "SignalResource on an unknown logical id",
    )

    # both stray signals must be inert — the stack stays CREATE_COMPLETE
    status = _describe_stack(cfn, name)["StackStatus"]
    assert status == "CREATE_COMPLETE", (
        f"expected the stray signals to be inert and the stack to remain CREATE_COMPLETE, got {status}"
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


def _must_succeed(fn, what):
    """Call fn(); a ClientError fails the check, since real AWS accepts the call."""
    try:
        return fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        raise AssertionError(
            f"expected {what} to be accepted, got {err.get('Code')}: {err.get('Message')}"
        ) from exc


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
