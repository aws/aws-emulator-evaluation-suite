"""get-stack-output-reads-unexported-output-as-snapshot."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-stack-output-reads-unexported-output-as-snapshot"
GROUP = 'cross_stack_references'
SERVICES = ['cloudformation']

_TERMINAL_STATES = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "UPDATE_COMPLETE", "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
}


def _describe(cf, name):
    """DescribeStacks for one stack, or None when it does not exist."""
    try:
        return cf.describe_stacks(StackName=name)["Stacks"][0]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ValidationError":
            return None
        raise


def _wait_terminal(cf, name, *, timeout_s=600, interval_s=5):
    """Poll DescribeStacks until the stack reaches a terminal state; return the stack."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        stack = _describe(cf, name)
        last = None if stack is None else stack["StackStatus"]
        if stack is not None and last in _TERMINAL_STATES:
            return stack
        if time.monotonic() >= deadline:
            raise AssertionError(f"stack {name} did not reach a terminal state within {timeout_s}s (last={last!r})")
        time.sleep(interval_s)


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; raises when the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _outputs(stack):
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}

def _producer(color):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}},
        "Outputs": {"Color": {"Value": color}},
    })


def _consumer(producer, marker):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle", "Metadata": {"Marker": marker}}},
        "Outputs": {
            "Seen": {"Value": {"Fn::GetStackOutput": {"StackName": producer, "OutputName": "Color"}}},
            "Marker": {"Value": marker},
        },
    })

@tags("axis:happy-path", "cap:c4", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A consumer stack resolves Fn::GetStackOutput against a producer output that has no Export; after
    the producer's output changes the consumer still reports the old value, and an update of the
    consumer resolves the new one."""
    cf = ctx.client("cloudformation")
    producer = ctx.unique_name("sim2real-behav-gso-prod-")
    consumer = ctx.unique_name("sim2real-behav-gso-cons-")

    cf.create_stack(StackName=producer, TemplateBody=_producer("red"))
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=producer))
    made = _wait_terminal(cf, producer)
    assert made["StackStatus"] == "CREATE_COMPLETE", f"producer create: {made['StackStatus']!r} {made.get('StackStatusReason')!r}"
    assert "ExportName" not in made["Outputs"][0], f"the producer output must not be exported: {made['Outputs']!r}"

    cf.create_stack(StackName=consumer, TemplateBody=_consumer(producer, "one"))
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=consumer))
    used = _wait_terminal(cf, consumer)
    assert used["StackStatus"] == "CREATE_COMPLETE", f"consumer create: {used['StackStatus']!r} {used.get('StackStatusReason')!r}"
    assert _outputs(used).get("Seen") == "red", f"the consumer must read the unexported output; got {_outputs(used)!r}"

    cf.update_stack(StackName=producer, TemplateBody=_producer("blue"))
    changed = _wait_terminal(cf, producer)
    assert changed["StackStatus"] == "UPDATE_COMPLETE", f"producer update: {changed['StackStatus']!r}"
    assert _outputs(changed).get("Color") == "blue", f"producer output after update: {_outputs(changed)!r}"

    stale = _describe(cf, consumer)
    assert _outputs(stale).get("Seen") == "red", (
        f"a GetStackOutput value is a snapshot; the consumer changed without an update: {_outputs(stale)!r}"
    )

    cf.update_stack(StackName=consumer, TemplateBody=_consumer(producer, "two"))
    refreshed = _wait_terminal(cf, consumer)
    assert refreshed["StackStatus"] == "UPDATE_COMPLETE", f"consumer update: {refreshed['StackStatus']!r}"
    assert _outputs(refreshed).get("Seen") == "blue", (
        f"updating the consumer must re-resolve the reference; got {_outputs(refreshed)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
