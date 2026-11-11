"""deep-cloudformation-3-cfn-flight-update-while-wait-condition-barriered-rejected-then-succeeds."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-cloudformation-3-cfn-flight-update-while-wait-condition-barriered-rejected-then-succeeds"
GROUP = "stack_updates"
SERVICES = ["cloudformation"]

_BASE = {"Resources": {"Anchor": {"Type": "AWS::CloudFormation::WaitConditionHandle"}}}

# Update 1 adds a WaitCondition governed by a CreationPolicy. It cannot complete until it
# receives one SignalResource call, so the stack is held in UPDATE_IN_PROGRESS by structure,
# not by timing.
_GATED = {"Resources": {
    "Anchor": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
    "Gate": {"Type": "AWS::CloudFormation::WaitCondition",
             "CreationPolicy": {"ResourceSignal": {"Count": 1, "Timeout": "PT15M"}}},
}}

# Update 2 is the competing update: the gated template plus one more handle.
_SECOND = {"Resources": {
    "Anchor": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
    "Gate": {"Type": "AWS::CloudFormation::WaitCondition",
             "CreationPolicy": {"ResourceSignal": {"Count": 1, "Timeout": "PT15M"}}},
    "Second": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
}}


@tags("cap:c3", "concern:negative-classes", "plane:control", "axis:rejection")
def run(ctx) -> None:
    """While an UpdateStack is held by an unsignalled WaitCondition, a second UpdateStack is
    refused; once the barrier is signalled and the first update completes, the same one applies."""
    cf = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-behav-cfnflight-upd-")
    stack_id = cf.create_stack(
        StackName=name, TemplateBody=json.dumps(_BASE),
        Tags=[{"Key": "sim2real-check", "Value": "cfn-flight"}],
    )["StackId"]
    ctx.on_cleanup(lambda: _release_and_delete(cf, stack_id))
    status = _wait_settled(cf, stack_id)
    assert status == "CREATE_COMPLETE", f"base stack ended {status!r}, expected 'CREATE_COMPLETE'"

    cf.update_stack(StackName=stack_id, TemplateBody=json.dumps(_GATED))
    # The barrier is up once the Gate resource is CREATE_IN_PROGRESS inside an UPDATE_IN_PROGRESS stack.
    _wait_resource_status(cf, stack_id, "Gate", "CREATE_IN_PROGRESS")
    held = _stack(cf, stack_id)["StackStatus"]
    assert held == "UPDATE_IN_PROGRESS", f"stack is {held!r} while the gate is open, expected 'UPDATE_IN_PROGRESS'"

    # Negative: the competing update is refused with the exact code and message.
    err = _client_error(lambda: cf.update_stack(StackName=stack_id, TemplateBody=json.dumps(_SECOND)))
    code = err.get("Code")
    assert code == "ValidationError", f"competing UpdateStack returned code {code!r}, expected 'ValidationError'"
    message = err.get("Message")
    assert message == f"Stack:{stack_id} is in UPDATE_IN_PROGRESS state and can not be updated.", (
        f"competing UpdateStack message was {message!r}"
    )
    # Effect absent: the refused update added nothing and did not release or abort the first one.
    assert "Second" not in _logical_ids(cf, stack_id), "the refused update's 'Second' resource was created anyway"
    gate = cf.describe_stack_resource(StackName=stack_id, LogicalResourceId="Gate")["StackResourceDetail"]
    assert gate["ResourceStatus"] == "CREATE_IN_PROGRESS", (
        f"the refusal disturbed the in-flight update: Gate is {gate['ResourceStatus']!r}"
    )
    held = _stack(cf, stack_id)["StackStatus"]
    assert held == "UPDATE_IN_PROGRESS", f"stack is {held!r} after the refusal, expected still 'UPDATE_IN_PROGRESS'"

    # Release the barrier; the first update must complete.
    cf.signal_resource(StackName=stack_id, LogicalResourceId="Gate",
                       UniqueId=ctx.unique_name("sig-"), Status="SUCCESS")
    status = _wait_settled(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"first update ended {status!r} after the signal, expected 'UPDATE_COMPLETE'"
    gate = cf.describe_stack_resource(StackName=stack_id, LogicalResourceId="Gate")["StackResourceDetail"]
    assert gate["ResourceStatus"] == "CREATE_COMPLETE", f"Gate is {gate['ResourceStatus']!r}, expected 'CREATE_COMPLETE'"

    # Positive control: the identical second UpdateStack is now accepted and applied.
    accepted = cf.update_stack(StackName=stack_id, TemplateBody=json.dumps(_SECOND))
    assert accepted.get("StackId") == stack_id, f"second UpdateStack returned {accepted.get('StackId')!r}, expected {stack_id!r}"
    status = _wait_settled(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"second update ended {status!r}, expected 'UPDATE_COMPLETE'"
    ids = _logical_ids(cf, stack_id)
    assert ids == {"Anchor", "Gate", "Second"}, f"after the second update the stack holds {sorted(ids)!r}"



def _client_error(fn) -> dict:
    """Call fn(); return the botocore Error dict. Raises if fn unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _stack(cf, stack_id: str) -> dict:
    return cf.describe_stacks(StackName=stack_id)["Stacks"][0]


def _logical_ids(cf, stack_id: str) -> set:
    ids = set()
    for page in cf.get_paginator("list_stack_resources").paginate(StackName=stack_id):
        ids.update(r["LogicalResourceId"] for r in page["StackResourceSummaries"]
                   if r["ResourceStatus"] != "DELETE_COMPLETE")
    return ids


def _wait_settled(cf, stack_id: str, timeout_s: float = 600.0) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = _stack(cf, stack_id)["StackStatus"]
        if not status.endswith("_IN_PROGRESS"):
            return status
        time.sleep(3)
    raise AssertionError(f"stack {stack_id} did not settle within {timeout_s}s (last={status!r})")


def _wait_resource_status(cf, stack_id: str, logical_id: str, want: str, timeout_s: float = 300.0) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = cf.describe_stack_resource(StackName=stack_id, LogicalResourceId=logical_id)[
                "StackResourceDetail"]["ResourceStatus"]
            if last == want:
                return
        except ClientError as exc:
            last = exc.response.get("Error", {}).get("Code")
        time.sleep(2)
    raise AssertionError(f"{logical_id} never reached {want!r} within {timeout_s}s (last={last!r})")


def _release_and_delete(cf, stack_id: str) -> None:
    """Fail the gate if it is still open (rolls the update back fast), then delete the stack."""
    try:
        if _stack(cf, stack_id)["StackStatus"].endswith("_IN_PROGRESS"):
            cf.signal_resource(StackName=stack_id, LogicalResourceId="Gate",
                               UniqueId="sim2real-cleanup", Status="FAILURE")
            _wait_settled(cf, stack_id)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise
    try:
        cf.delete_stack(StackName=stack_id)
        _wait_settled(cf, stack_id)
    except Exception as exc:
        raise RuntimeError(f"stack {stack_id}: {exc}") from exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
