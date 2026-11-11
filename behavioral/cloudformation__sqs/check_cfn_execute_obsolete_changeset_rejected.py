"""cfn-execute-obsolete-changeset-rejected."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-execute-obsolete-changeset-rejected"

GROUP = "change_sets"

SERVICES = ["cloudformation", "sqs"]

_TEMPLATE = json.dumps({
    "Parameters": {"QueueName": {"Type": "String"}, "Timeout": {"Type": "Number"}},
    "Resources": {
        "Queue": {"Type": "AWS::SQS::Queue",
                  "Properties": {"QueueName": {"Ref": "QueueName"},
                                 "VisibilityTimeout": {"Ref": "Timeout"}}},
    },
})


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Executing one change set obsoletes every other outstanding change set on the same stack:
    the untouched one becomes OBSOLETE, executing it raises InvalidChangeSetStatus, and its value
    was never applied.
    """
    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")

    queue_name = _xname(ctx, "obs-q")
    ctx.on_cleanup(lambda: _delete_queue_by_name_if_present(sqs, queue_name))

    stack, status = _create_stack_and_wait(
        ctx, _TEMPLATE, stack_name=_xname(ctx, "obs"),
        parameters={"QueueName": queue_name, "Timeout": "30"}, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", f"setup stack ended in {status!r}"
    queue_url = _physical_id(cfn, stack, "Queue")
    assert _visibility_timeout(sqs, queue_url) == "30", (
        f"setup did not take: {_visibility_timeout(sqs, queue_url)!r}"
    )

    # Both change sets exist BEFORE either is executed -- that is the precondition the claim is
    # about. Two genuinely different values, because a change set with no changes fails to create.
    cs_a = _create_change_set(ctx, stack, _xname(ctx, "obs-csa"), queue_name, "40")
    cs_b = _create_change_set(ctx, stack, _xname(ctx, "obs-csb"), queue_name, "50")
    before_a = _change_set(cfn, cs_a)["ExecutionStatus"]
    before_b = _change_set(cfn, cs_b)["ExecutionStatus"]
    assert before_a == "AVAILABLE", f"change set A was not AVAILABLE before the update: {before_a!r}"
    assert before_b == "AVAILABLE", f"change set B was not AVAILABLE before the update: {before_b!r}"

    cfn.execute_change_set(ChangeSetName=cs_b)
    executed = _poll_until(lambda: _stack_status(cfn, stack), lambda s: s in _UPDATE_TERMINAL,
                           timeout_s=900.0, interval_s=5.0, description=f"update of {stack}")
    assert executed == "UPDATE_COMPLETE", f"executing change set B ended in {executed!r}"

    # 1. A's ExecutionStatus is exactly OBSOLETE -- not merely 'not AVAILABLE'.
    after_a = _change_set(cfn, cs_a)["ExecutionStatus"]
    assert after_a == "OBSOLETE", (
        f"expected ExecutionStatus OBSOLETE after a sibling change set executed, got {after_a!r}"
    )

    # 2. Executing it is refused with one exact code.
    code, message = _error(lambda: cfn.execute_change_set(ChangeSetName=cs_a))
    assert code == "InvalidChangeSetStatus", (
        f"expected InvalidChangeSetStatus when executing an OBSOLETE change set, got {code!r}"
    )
    expected = f"ChangeSet [{cs_a}] cannot be executed in its current execution status of [OBSOLETE]"
    assert message == expected, f"refusal message {message!r} != {expected!r}"

    # 3. The effect is ABSENT: A's value never reached the queue, B's did.
    live = _visibility_timeout(sqs, queue_url)
    assert live == "50", (
        f"the obsolete change set's value must never have been applied: the queue reports "
        f"{live!r}, expected B's '50' (A wanted '40')"
    )

    # Control: a change set created afterwards still executes, so the stack is not wedged.
    cs_c = _create_change_set(ctx, stack, _xname(ctx, "obs-csc"), queue_name, "60")
    cfn.execute_change_set(ChangeSetName=cs_c)
    control_status = _poll_until(lambda: _stack_status(cfn, stack), lambda s: s in _UPDATE_TERMINAL,
                                timeout_s=900.0, interval_s=5.0,
                                description=f"control update of {stack}")
    assert control_status == "UPDATE_COMPLETE", (
        f"the stack is wedged: a change set created after the update ended in "
        f"{control_status!r}, so the refusal above proves nothing about obsoleting"
    )
    assert _visibility_timeout(sqs, queue_url) == "60", (
        f"the control change set did not land: {_visibility_timeout(sqs, queue_url)!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_NO_SUCH_QUEUE = "AWS.SimpleQueueService.NonExistentQueue"

_CREATE_TERMINAL = {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
                    "DELETE_COMPLETE", "DELETE_FAILED", "GONE"}

_UPDATE_TERMINAL = {"UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE",
                    "UPDATE_ROLLBACK_FAILED", "GONE"}


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": _XSVC_PREFIX.rstrip("-")}]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _error(fn) -> tuple[str, str | None]:
    """The AWS (code, message) fn() raises. Raises AssertionError if fn() succeeds."""
    try:
        ok = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message")
    raise AssertionError(f"expected this call to fail, but it succeeded and returned {ok!r}")


def _queue_url_or_none(sqs, name: str) -> str | None:
    try:
        return sqs.get_queue_url(QueueName=name)["QueueUrl"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == _NO_SUCH_QUEUE:
            return None
        raise


def _delete_queue_by_name_if_present(sqs, name: str) -> None:
    """Best-effort queue teardown by name; already-deleted is not an error."""
    url = _queue_url_or_none(sqs, name)
    if url:
        sqs.delete_queue(QueueUrl=url)


def _visibility_timeout(sqs, url: str) -> str:
    return sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["VisibilityTimeout"])["Attributes"]["VisibilityTimeout"]


def _stack_status(cfn, name: str) -> str:
    try:
        return cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
    except ClientError:
        return "GONE"


def _physical_id(cfn, stack: str, logical_id: str) -> str:
    """The PhysicalResourceId CloudFormation currently records for a logical id."""
    return cfn.describe_stack_resource(
        StackName=stack, LogicalResourceId=logical_id)["StackResourceDetail"]["PhysicalResourceId"]


def _change_set(cfn, change_set_id: str) -> dict[str, Any]:
    """DescribeChangeSet with its Changes paginated in."""
    out: dict[str, Any] = {}
    changes: list[dict[str, Any]] = []
    token = None
    while True:
        kwargs: dict[str, Any] = {"ChangeSetName": change_set_id}
        if token:
            kwargs["NextToken"] = token
        page = cfn.describe_change_set(**kwargs)
        out = page
        changes.extend(page.get("Changes", []))
        token = page.get("NextToken")
        if not token:
            break
    out["Changes"] = changes
    return out


def _create_change_set(ctx, stack: str, name: str, queue_name: str, timeout: str) -> str:
    """Create a parameter-only change set on `stack` and poll it to a terminal Status.

    Returns the change set ID, which is what ExecuteChangeSet needs once the stack has several.
    """
    cfn = ctx.client("cloudformation")
    cs_id = cfn.create_change_set(
        StackName=stack, ChangeSetName=name, ChangeSetType="UPDATE", UsePreviousTemplate=True,
        Parameters=[{"ParameterKey": "QueueName", "ParameterValue": queue_name},
                    {"ParameterKey": "Timeout", "ParameterValue": timeout}],
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    )["Id"]
    # Change sets die with the stack, but an AVAILABLE one left behind clutters the account.
    ctx.on_cleanup(lambda: _delete_change_set_if_present(cfn, cs_id))
    final = _poll_until(lambda: _change_set(cfn, cs_id)["Status"],
                        lambda s: s in {"CREATE_COMPLETE", "FAILED"},
                        timeout_s=300.0, interval_s=3.0, description=f"change set {name}")
    assert final == "CREATE_COMPLETE", (
        f"change set {name!r} ended {final!r}: {_change_set(cfn, cs_id).get('StatusReason')!r}"
    )
    return cs_id


def _delete_change_set_if_present(cfn, change_set_id: str) -> None:
    try:
        cfn.delete_change_set(ChangeSetName=change_set_id)
    except ClientError as exc:
        # An executed change set cannot be deleted; it goes with its stack.
        tolerated = {"ChangeSetNotFound", "ValidationError", "InvalidChangeSetStatus"}
        if exc.response.get("Error", {}).get("Code") not in tolerated:
            raise


def _delete_stack_and_wait(ctx, name: str, *, timeout_s=900.0) -> None:
    """Delete a stack and wait for it to go; only a not-found error is tolerated."""
    cfn = ctx.client("cloudformation")
    try:
        cfn.delete_stack(StackName=name)
        final = _poll_until(lambda: _stack_status(cfn, name),
                            lambda s: s in {"DELETE_COMPLETE", "GONE", "DELETE_FAILED"},
                            timeout_s=timeout_s, interval_s=5.0,
                            description=f"delete stack {name}")
        if final == "DELETE_FAILED":
            raise RuntimeError(
                f"stack {name} ended DELETE_FAILED — its resources are stranded"
            )
    except Exception as exc:  # noqa: BLE001 - only a not-found is tolerated
        teardown_code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
        if (
            not any(t in teardown_code for t in ("NotFound", "NoSuch", "NonExistent", "DoesNotExist"))
        ):
            raise RuntimeError(
                f"stack {name} teardown failed: {type(exc).__name__}: {exc}"
            ) from exc


def _create_stack_and_wait(ctx, template: str, *, stack_name=None, parameters=None,
                           capabilities=None, timeout_s=900.0) -> tuple[str, str]:
    """create_stack, then poll to a terminal status which is RETURNED rather than asserted."""
    cfn = ctx.client("cloudformation")
    ctx.verify_account_safety()
    name = stack_name or _xname(ctx, "stk")
    kwargs: dict[str, Any] = {
        "StackName": name, "TemplateBody": template, "Tags": _tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [{"ParameterKey": k, "ParameterValue": v}
                                for k, v in parameters.items()]
    cfn.create_stack(**kwargs)
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name, timeout_s=timeout_s))
    status = _poll_until(lambda: _stack_status(cfn, name), lambda s: s in _CREATE_TERMINAL,
                         timeout_s=timeout_s, interval_s=5.0,
                         description=f"create stack {name}")
    return name, status


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
