"""list-stacks-status-filter-includes-deleted."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-stacks-status-filter-includes-deleted"
GROUP = 'listing'
SERVICES = ['cloudformation']


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListStacks(StackStatusFilter=[...]) genuinely filters by current status: a deleted
    stack shows up under DELETE_COMPLETE but never under CREATE_COMPLETE once it's gone."""
    cfn = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-behav-stack-listfilt-")
    cfn.create_stack(StackName=name, TemplateBody=_sns_template())
    ctx.on_cleanup(lambda: _delete_stack_quiet(cfn, name))
    _wait_stack_status(cfn, name, {"CREATE_COMPLETE"})

    active = _list_stacks(cfn, ["CREATE_COMPLETE"])
    assert any(s["StackName"] == name for s in active), "must appear while CREATE_COMPLETE"

    cfn.delete_stack(StackName=name)
    _wait_stack_deleted(cfn, name)

    active_after = _list_stacks(cfn, ["CREATE_COMPLETE"])
    assert not any(s["StackName"] == name for s in active_after), (
        "a deleted stack must not appear under CREATE_COMPLETE anymore"
    )

    deleted = _list_stacks(cfn, ["DELETE_COMPLETE"])
    matches = [s for s in deleted if s["StackName"] == name]
    assert matches, "the deleted stack must appear under DELETE_COMPLETE"
    assert matches[0]["StackStatus"] == "DELETE_COMPLETE", matches[0]


def _list_stacks(cfn, statuses):
    """Every StackSummary ListStacks returns for the status filter, across pages."""
    pages = cfn.get_paginator("list_stacks").paginate(StackStatusFilter=statuses)
    return [s for page in pages for s in page.get("StackSummaries", [])]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _sns_template() -> str:
    return json.dumps(
        {
            "Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": {}}},
            "Outputs": {"TopicArn": {"Value": {"Ref": "Topic"}}},
        }
    )


def _describe_stack(cfn, name):
    stacks = cfn.describe_stacks(StackName=name).get("Stacks", [])
    return stacks[0] if stacks else None


def _wait_stack_status(cfn, name, target_statuses, timeout_s=180, interval_s=3):
    target = set(target_statuses) if not isinstance(target_statuses, str) else {target_statuses}
    return _poll_until(
        lambda: _describe_stack(cfn, name),
        lambda stack: stack is not None and stack.get("StackStatus") in target,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"stack {name} reaching {sorted(target)}",
    )


def _wait_stack_deleted(cfn, name, timeout_s=180, interval_s=3):
    def probe():
        try:
            return _describe_stack(cfn, name)
        except Exception as exc:  # noqa: BLE001 — a gone stack stops resolving by name
            if "does not exist" in str(exc):
                return "GONE"
            raise

    return _poll_until(
        probe,
        lambda val: val == "GONE"
        or (val is not None and val.get("StackStatus") == "DELETE_COMPLETE"),
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"stack {name} being deleted",
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
