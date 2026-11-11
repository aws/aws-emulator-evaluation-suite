"""signal-resource-invalid-status-rejected."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "signal-resource-invalid-status-rejected"
GROUP = 'resources'
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

def _reject_or_raise(fn):
    """Call fn(); return the botocore (Code, Message) if rejected; raise if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected SignalResource to be rejected, but it succeeded: {result!r}")

def _wait_resource_blocked(cf, name, logical_id, timeout_s=60):
    """Poll DescribeStackResource until the resource is CREATE_IN_PROGRESS; raise on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = cf.describe_stack_resource(
                StackName=name, LogicalResourceId=logical_id
            )["StackResourceDetail"].get("ResourceStatus")
        except ClientError as exc:
            last = exc.response.get("Error", {}).get("Code")
        if last == "CREATE_IN_PROGRESS":
            return
        time.sleep(2)
    raise AssertionError(
        f"resource {logical_id} of stack {name} not CREATE_IN_PROGRESS within {timeout_s}s (last={last!r})"
    )

def _signal_wait_condition_template(timeout_iso="PT2M", count=1):
    """A WaitCondition with a CreationPolicy and no handle, which SignalResource signals directly.
    It stays CREATE_IN_PROGRESS until `count` SUCCESS signals arrive or `timeout_iso` elapses."""
    return json.dumps(
        {
            "Resources": {
                "Waiter": {
                    "Type": "AWS::CloudFormation::WaitCondition",
                    "CreationPolicy": {
                        "ResourceSignal": {"Timeout": timeout_iso, "Count": count}
                    },
                }
            }
        }
    )


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SignalResource rejects a Status outside [SUCCESS, FAILURE] with ValidationError and leaves
    the resource CREATE_IN_PROGRESS; a real SUCCESS signal then completes the stack creation."""
    cf = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-behav-sig-badstatus-")
    cf.create_stack(StackName=name, TemplateBody=_signal_wait_condition_template())
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=name))

    # Wait for the resource to actually be blocked mid-creation before signaling: the
    # WaitCondition holds CREATE_IN_PROGRESS until a SUCCESS signal arrives.
    _wait_resource_blocked(cf, name, "Waiter", timeout_s=60)

    code, message = _reject_or_raise(
        lambda: cf.signal_resource(
            StackName=name,
            LogicalResourceId="Waiter",
            UniqueId="sim2real-behav-signal-badstatus",
            Status="MAYBE_LATER",
        )
    )
    assert code == "ValidationError", (
        f"SignalResource with an invalid Status enum value should be rejected with "
        f"ValidationError, got {code!r}"
    )
    assert message == (
        "1 validation error detected: Value 'MAYBE_LATER' at 'status' failed to satisfy "
        "constraint: Member must satisfy enum value set: [SUCCESS, FAILURE]"
    ), message

    # effect absent: the rejected signal must not have advanced the resource past the
    # point where it was still waiting for a real signal.
    after_bad = cf.describe_stack_resource(
        StackName=name, LogicalResourceId="Waiter"
    )["StackResourceDetail"]
    assert after_bad["ResourceStatus"] == "CREATE_IN_PROGRESS", (
        f"the rejected Status=MAYBE_LATER signal changed the resource to "
        f"{after_bad['ResourceStatus']!r}, expected it to still be CREATE_IN_PROGRESS"
    )

    # positive control: the identical channel accepts a real SUCCESS signal and the
    # stack actually completes — proving the rejection above is specific to the bad
    # Status value, not a symptom of a channel that rejects everything.
    try:
        cf.signal_resource(
            StackName=name,
            LogicalResourceId="Waiter",
            UniqueId="sim2real-behav-signal-good",
            Status="SUCCESS",
        )
    except ClientError as exc:
        raise AssertionError(
            f"a valid SUCCESS signal was rejected: {exc.response.get('Error')}"
        ) from exc

    final_status = _wait_terminal(cf, name, timeout_s=180)
    assert final_status == "CREATE_COMPLETE", (
        f"expected the stack to reach CREATE_COMPLETE after the valid SUCCESS signal, "
        f"got {final_status!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
