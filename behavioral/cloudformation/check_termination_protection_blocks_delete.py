"""termination-protection-blocks-delete."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "termination-protection-blocks-delete"
GROUP = 'termination_protection'
SERVICES = ['cloudformation']
#: Bounded convergence for a stack transition (create, delete, gone).
POLL_BUDGET_S = 180.0


_TERMINAL_STATES = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "UPDATE_COMPLETE", "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE",
    "IMPORT_ROLLBACK_COMPLETE", "IMPORT_ROLLBACK_FAILED",
}

def _wait_terminal(cf, name, timeout_s=POLL_BUDGET_S):
    """Poll DescribeStacks until the stack reaches a terminal state; return it."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        # A just-created stack is always describable, so any ClientError propagates.
        last = cf.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
        if last in _TERMINAL_STATES:
            return last
        time.sleep(2)
    raise AssertionError(f"stack {name} terminal not met within {timeout_s}s (last={last!r})")

def _delete_protected(cf, name):
    """Teardown for a termination-protected stack: disable protection, then delete. Only a stack
    that no longer exists is tolerated; every other error raises."""
    try:
        cf.update_termination_protection(StackName=name, EnableTerminationProtection=False)
        cf.delete_stack(StackName=name)
    except ClientError as exc:
        err = exc.response.get("Error", {})
        if err.get("Code") != "ValidationError" or "does not exist" not in (err.get("Message") or ""):
            raise

def _refusal(exc, *, status=400):
    """(code, message) of a ClientError, after grading its HTTP status class."""
    err = exc.response.get('Error', {})
    got_status = exc.response.get('ResponseMetadata', {}).get('HTTPStatusCode')
    assert isinstance(got_status, int) and got_status // 100 == status // 100, (
        f"expected HTTP {status // 100}xx with {err.get('Code')}, got {got_status!r}"
    )
    return err.get('Code'), err.get('Message')


def _refused(fn, *, status=400):
    """(code, message) of the ClientError fn() raises; an accepted call is itself a failure."""
    try:
        result = fn()
    except ClientError as exc:
        return _refusal(exc, status=status)
    raise AssertionError(f'expected a refusal, but the call succeeded: {result!r}')


_ACTIVE_STACK_STATUSES = [
    "CREATE_IN_PROGRESS", "CREATE_FAILED", "CREATE_COMPLETE", "ROLLBACK_IN_PROGRESS",
    "ROLLBACK_FAILED", "ROLLBACK_COMPLETE", "DELETE_IN_PROGRESS", "DELETE_FAILED",
    "UPDATE_IN_PROGRESS", "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS", "UPDATE_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_IN_PROGRESS", "UPDATE_ROLLBACK_FAILED",
    "UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS", "UPDATE_ROLLBACK_COMPLETE",
    "REVIEW_IN_PROGRESS", "IMPORT_IN_PROGRESS", "IMPORT_COMPLETE",
    "IMPORT_ROLLBACK_IN_PROGRESS", "IMPORT_ROLLBACK_FAILED", "IMPORT_ROLLBACK_COMPLETE",
]


def _assert_stack_gone(cf, name):
    """The three gone beats for a deleted stack: not found by name, unlisted, not updatable."""
    # DescribeStacks by name of a deleted stack is refused ValidationError (polled: the by-name
    # lookup converges once DELETE_COMPLETE is reached).
    got = _poll_refused(lambda: cf.describe_stacks(StackName=name))
    assert got == ("ValidationError", f"Stack with id {name} does not exist"), (
        f"DescribeStacks on the deleted stack: got {got!r}"
    )
    # ListStacks keeps DELETE_COMPLETE summaries for 90 days, so only the active statuses are asked for.
    listed = [s["StackName"] for page in cf.get_paginator("list_stacks").paginate(
        StackStatusFilter=_ACTIVE_STACK_STATUSES) for s in page.get("StackSummaries", [])]
    assert name not in listed, f"deleted stack {name} still listed among active stacks"
    # UpdateStack(TemplateBody=...) on a missing stack is refused ValidationError.
    got = _refused(lambda: cf.update_stack(StackName=name, TemplateBody=_DEAD_STACK_TEMPLATE))
    assert got == ("ValidationError", f"Stack [{name}] does not exist"), (
        f"UpdateStack on the deleted stack: got {got!r}"
    )


_DEAD_STACK_TEMPLATE = '{"Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}}}'


def _poll_refused(fn):
    """Repeat fn() until it is refused (bounded convergence), then return the refusal's
    (code, message)."""
    deadline = time.monotonic() + POLL_BUDGET_S
    while True:
        try:
            result = fn()
        except ClientError as exc:
            return _refusal(exc)
        if time.monotonic() > deadline:
            raise AssertionError(f"expected a refusal within {POLL_BUDGET_S}s, still accepted: {result!r}")
        time.sleep(5)


def _wait_deleted(cf, name, timeout_s=POLL_BUDGET_S):
    """Poll until the stack reports DELETE_COMPLETE or DescribeStacks says it no longer exists."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = cf.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
            if last == "DELETE_COMPLETE":
                return last
            if last == "DELETE_FAILED":
                raise AssertionError(f"stack {name} reached DELETE_FAILED")
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ValidationError":
                return "GONE"
            raise
        time.sleep(2)
    raise AssertionError(f"stack {name} not deleted within {timeout_s}s (last={last!r})")

def _handle_template():
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}},
    })


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A stack with termination protection enabled cannot be deleted; the stack is left
    completely untouched by the rejected call; and disabling protection lets the identical
    DeleteStack call succeed (positive control)."""
    cf = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-behav-stk-")
    cf.create_stack(
        StackName=name,
        TemplateBody=_handle_template(),
        EnableTerminationProtection=True,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_protected(cf, name))
    _wait_terminal(cf, name)

    got = _refused(lambda: cf.delete_stack(StackName=name))
    blocked = ("ValidationError", f"Stack [{name}] cannot be deleted while TerminationProtection is enabled")
    assert got == blocked, f"DeleteStack on a protected stack: expected {blocked}, got {got!r}"

    # effect absent: an independent read shows the stack untouched and still protected
    stack = cf.describe_stacks(StackName=name)["Stacks"][0]
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"stack should be untouched after the blocked delete, got {stack['StackStatus']!r}"
    )
    assert stack["EnableTerminationProtection"] is True, (
        "stack should still report termination protection enabled after the blocked delete"
    )

    # positive control: disable protection, then the identical DeleteStack call succeeds
    cf.update_termination_protection(StackName=name, EnableTerminationProtection=False)
    cf.delete_stack(StackName=name)
    status = _wait_deleted(cf, name)
    assert status in ("DELETE_COMPLETE", "GONE"), (
        f"expected the identical DeleteStack call to succeed once protection is off, last={status!r}"
    )
    _assert_stack_gone(cf, name)
    got = _refused(lambda: cf.update_termination_protection(StackName=name, EnableTerminationProtection=True))
    assert got == ("ValidationError", f"Stack [{name}] does not exist"), (
        f"UpdateTerminationProtection on the deleted stack: got {got!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
