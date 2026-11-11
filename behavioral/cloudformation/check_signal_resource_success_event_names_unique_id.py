"""signal-resource-success-event-names-unique-id."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "signal-resource-success-event-names-unique-id"
GROUP = 'signal'
SERVICES = ['cloudformation']


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 5 s so the wait fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _timed_out(ctx, message):
    """The error a capped wait raises: TimeoutError when the run budget ended it, else a failure."""
    if _budget_spent(ctx):
        raise TimeoutError(f"run budget spent: {message}")
    raise AssertionError(message)


def _wait_for_resource_status(ctx, cf, stack_name, logical_id, target_statuses, cap_s=90.0, interval_s=2.0):
    """Poll DescribeStackResource until the resource reaches one of ``target_statuses``; only
    AWS's exact "resource does not exist yet" refusal is retried."""
    not_yet = ("ValidationError", f"Resource {logical_id} does not exist for stack {stack_name}")
    deadline = time.monotonic() + _budget_s(ctx, cap_s)
    last = None
    while time.monotonic() < deadline:
        try:
            last = cf.describe_stack_resource(
                StackName=stack_name, LogicalResourceId=logical_id
            )["StackResourceDetail"]["ResourceStatus"]
        except ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) != not_yet:
                raise
            last = None
        if last in target_statuses:
            return last
        time.sleep(interval_s)
    _timed_out(ctx, f"resource {logical_id} in {stack_name} did not reach {target_statuses} (last={last!r})")


def _wait_for_stack_status(ctx, cf, stack_name, terminal_statuses, cap_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + _budget_s(ctx, cap_s)
    last = None
    while time.monotonic() < deadline:
        last = cf.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if last in terminal_statuses:
            return last
        time.sleep(interval_s)
    _timed_out(ctx, f"stack {stack_name} did not reach {terminal_statuses} (last={last!r})")


def _events_for(cf, stack_name, logical_id):
    pages = cf.get_paginator("describe_stack_events").paginate(StackName=stack_name)
    return [e for page in pages for e in page["StackEvents"] if e["LogicalResourceId"] == logical_id]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A SUCCESS SignalResource for a CreationPolicy resource leaves a stack event for that
    resource whose ResourceStatusReason names the signal's own UniqueId."""
    cf = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-sig-event-")

    template = json.dumps({
        "Resources": {
            "Waiter": {
                "Type": "AWS::CloudFormation::WaitCondition",
                # Count=2 so the first signal alone leaves the resource waiting, and both
                # signals must be tracked by their own UniqueId rather than only the last one.
                "CreationPolicy": {"ResourceSignal": {"Count": 2, "Timeout": "PT5M"}},
            },
        },
    })
    cf.create_stack(StackName=stack_name, TemplateBody=template)
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=stack_name))

    _wait_for_resource_status(ctx, cf, stack_name, "Waiter", {"CREATE_IN_PROGRESS"})

    first_id = ctx.unique_name("sig-first-")
    cf.signal_resource(
        StackName=stack_name, LogicalResourceId="Waiter", UniqueId=first_id, Status="SUCCESS",
    )
    second_id = ctx.unique_name("sig-second-")
    cf.signal_resource(
        StackName=stack_name, LogicalResourceId="Waiter", UniqueId=second_id, Status="SUCCESS",
    )

    status = _wait_for_stack_status(ctx, cf, stack_name, {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE"})
    assert status == "CREATE_COMPLETE", f"the two SUCCESS signals should have unblocked creation, got {status!r}"

    reasons = [e.get("ResourceStatusReason") for e in _events_for(cf, stack_name, "Waiter")]
    first_expected = f"Received SUCCESS signal with UniqueId {first_id}"
    second_expected = f"Received SUCCESS signal with UniqueId {second_id}"
    assert first_expected in reasons, (
        f"expected a stack event for Waiter whose ResourceStatusReason names the first "
        f"signal's UniqueId {first_id!r}, got reasons {reasons!r}"
    )
    assert second_expected in reasons, (
        f"expected a stack event for Waiter whose ResourceStatusReason names the second "
        f"signal's UniqueId {second_id!r}, got reasons {reasons!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
