"""signal-resource-wait-condition-timeout."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "signal-resource-wait-condition-timeout"
GROUP = 'stack_lifecycle'
SERVICES = ['cloudformation']


def _error_code(fn):
    """Call fn(); return botocore (Code, Message) if a ClientError is raised. An unexpected SUCCESS
    raises, because a target accepting a call real AWS refuses is the strongest signal
    available and must never be reported as a mere code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

def _poll_until(probe, predicate, timeout_s=60, interval_s=2):
    """Poll probe() until predicate(result) is truthy; return the last result. Raise on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")

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

def _signal_wait_condition_template(timeout_iso="PT1M", count=1):
    """A bare AWS::CloudFormation::WaitCondition with a CreationPolicy.ResourceSignal."""
    return json.dumps({
        "Resources": {
            "Waiter": {
                "Type": "AWS::CloudFormation::WaitCondition",
                "CreationPolicy": {"ResourceSignal": {"Timeout": timeout_iso, "Count": count}},
            }
        }
    })


# timing:real-time — workflow: 60 s https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-creationpolicy.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control", "timing:real-time")
def run(ctx) -> None:
    """A WaitCondition governed by a CreationPolicy.ResourceSignal completes the stack
    well before its Timeout when signaled in time, and rolls the stack back once that
    Timeout elapses unsignaled; SignalResource against a nonexistent stack is rejected."""
    cf = ctx.client("cloudformation")

    # --- Part A: signal arrives in time -> CREATE_COMPLETE fast ---------
    name_ok = ctx.unique_name("sim2real-behav-sig-ok-")
    id_ok = cf.create_stack(
        StackName=name_ok, TemplateBody=_signal_wait_condition_template(timeout_iso="PT10M", count=1)
    )["StackId"]
    ctx.on_cleanup(lambda: _teardown_stack(cf, id_ok))

    # Wait for the resource to actually be blocked mid-creation before signaling.
    def resource_in_progress():
        try:
            return cf.describe_stack_resource(
                StackName=name_ok, LogicalResourceId="Waiter"
            )["StackResourceDetail"]
        except ClientError:
            return None

    _poll_until(
        resource_in_progress,
        lambda r: r is not None and r.get("ResourceStatus") == "CREATE_IN_PROGRESS",
        timeout_s=60,
        interval_s=2,
    )

    started = time.monotonic()
    cf.signal_resource(
        StackName=name_ok,
        LogicalResourceId="Waiter",
        UniqueId="sim2real-behav-signal-1",
        Status="SUCCESS",
    )
    stack = _wait_stack_status(
        cf, name_ok, {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE"}, timeout_s=120
    )
    elapsed = time.monotonic() - started
    assert stack["StackStatus"] == "CREATE_COMPLETE", stack.get("StackStatusReason")
    # 10 minutes is the configured timeout; an in-time signal must complete in well under the
    # 120 s poll window, proving the signal -- not the timeout -- unblocked it.
    assert elapsed < 90, f"signaled stack took {elapsed:.1f}s to complete, timeout window is unrelated"
    waiter_ok = cf.describe_stack_resource(
        StackName=name_ok, LogicalResourceId="Waiter"
    )["StackResourceDetail"]
    assert waiter_ok["ResourceStatus"] == "CREATE_COMPLETE", waiter_ok

    # Overly-permissive boundary: SignalResource against a StackName that
    # doesn't exist at all must be rejected, not silently accepted.
    bogus_stack = ctx.unique_name("sim2real-behav-sig-nostack-")
    code, message = _error_code(
        lambda: cf.signal_resource(
            StackName=bogus_stack,
            LogicalResourceId="Waiter",
            UniqueId="sim2real-behav-signal-bogus",
            Status="SUCCESS",
        )
    )
    assert code == "ValidationError", f"expected ValidationError, got {code}"
    assert message == f"Stack {bogus_stack} does not exist", message

    # --- Part B: signal never arrives -> timeout fires -> rollback ------
    name_to = ctx.unique_name("sim2real-behav-sig-timeout-")
    id_to = cf.create_stack(
        StackName=name_to, TemplateBody=_signal_wait_condition_template(timeout_iso="PT1M", count=1)
    )["StackId"]
    ctx.on_cleanup(lambda: _teardown_stack(cf, id_to))

    started_to = time.time()
    stack_to = _wait_stack_status(
        cf, name_to, {"ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "CREATE_COMPLETE"}, timeout_s=240, interval_s=5
    )
    elapsed_to = time.time() - started_to
    assert stack_to["StackStatus"] == "ROLLBACK_COMPLETE", stack_to.get("StackStatusReason")
    # The 1-minute ResourceSignal timeout must actually have been honored
    # (not fired instantly, and not hung indefinitely).
    assert elapsed_to >= 30, f"rollback fired suspiciously fast ({elapsed_to:.1f}s) for a 1-minute timeout"

    resource_to = cf.describe_stack_resource(
        StackName=name_to, LogicalResourceId="Waiter"
    )["StackResourceDetail"]
    assert resource_to["ResourceStatus"] == "DELETE_COMPLETE", resource_to


def _teardown_stack(cfn, stack_id: str, *, timeout_s: float = 600.0) -> None:
    """Delete the stack by StackId and poll to DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    prior = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if prior == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    moved = False
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        status = stack["StackStatus"]
        moved = moved or status != prior
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED" and moved:
            raise AssertionError(f"stack {stack_id} teardown ended DELETE_FAILED: {stack.get('StackStatusReason')!r}")
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status} {timeout_s}s after DeleteStack")
        time.sleep(5.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
