"""create-stack-client-request-token-semantics."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-stack-client-request-token-semantics"
GROUP = 'idempotency'
SERVICES = ['cloudformation']


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ClientRequestToken is stamped onto every StackEvent of the operation, and is scoped
    per-stack-operation: the same token may be reused for a different stack (no conflict)."""
    cfn = ctx.client("cloudformation")
    name1 = ctx.unique_name("sim2real-behav-cfn-tok1-")
    name2 = ctx.unique_name("sim2real-behav-cfn-tok2-")
    token = ctx.unique_name("tok-token-")
    tmpl1 = _sns_topic_template(ctx.unique_name("sim2real-behav-cfn-topic-"))
    tmpl2 = _sns_topic_template(ctx.unique_name("sim2real-behav-cfn-topic-"))

    cfn.create_stack(StackName=name1, TemplateBody=tmpl1, ClientRequestToken=token)
    ctx.on_cleanup(lambda: _delete_stack_quiet(cfn, name1))
    first = _wait_stack_status(cfn, name1)
    assert first["StackStatus"] == "CREATE_COMPLETE", (
        f"expected CREATE_COMPLETE for {name1}, got {first['StackStatus']}"
    )

    # every event produced by that operation carries the caller's token
    events = cfn.describe_stack_events(StackName=name1)["StackEvents"]
    assert events, "expected stack events"
    assert all(e.get("ClientRequestToken") == token for e in events), [
        e.get("ClientRequestToken") for e in events
    ]

    # the token is NOT globally unique — reusing it on a different stack is accepted
    ctx.on_cleanup(lambda: _delete_stack_quiet(cfn, name2))
    try:
        cfn.create_stack(StackName=name2, TemplateBody=tmpl2, ClientRequestToken=token)
    except ClientError as exc:
        raise AssertionError(
            f"reusing a token for a different stack must be accepted, got "
            f"{exc.response.get('Error', {}).get('Code')}"
        ) from exc
    second = _wait_stack_status(cfn, name2)
    assert second["StackStatus"] == "CREATE_COMPLETE", (
        f"expected CREATE_COMPLETE for {name2}, got {second['StackStatus']}"
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


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _sns_topic_template(topic_name, display_name=None, export_name=None) -> str:
    props = {"TopicName": topic_name}
    if display_name is not None:
        props["DisplayName"] = display_name
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {"MyTopic": {"Type": "AWS::SNS::Topic", "Properties": props}},
            "Outputs": {
                "TopicArnOutput": {
                    "Value": {"Ref": "MyTopic"},
                    **({"Export": {"Name": export_name}} if export_name else {}),
                }
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
