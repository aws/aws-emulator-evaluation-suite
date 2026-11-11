"""cfn-stack-policy-protected-resource-replacement-rejected."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-stack-policy-protected-resource-replacement-rejected"

GROUP = "overly-permissive"

SERVICES = ["cloudformation", "sqs"]

_TEMPLATE = json.dumps({
    "Parameters": {
        "ProtectedName": {"Type": "String"},
        "OpenName": {"Type": "String"},
        "OpenTimeout": {"Type": "Number"},
    },
    "Resources": {
        # QueueName is a create-only property, so renaming Protected is a REPLACEMENT -- which is
        # the action the stack policy denies. VisibilityTimeout is mutable in place, so Open's
        # change is a MODIFY the policy allows.
        "Protected": {"Type": "AWS::SQS::Queue",
                      "Properties": {"QueueName": {"Ref": "ProtectedName"},
                                     "VisibilityTimeout": 30}},
        "Open": {"Type": "AWS::SQS::Queue",
                 "Properties": {"QueueName": {"Ref": "OpenName"},
                                "VisibilityTimeout": {"Ref": "OpenTimeout"}}},
    },
    "Outputs": {"ProtectedUrl": {"Value": {"Ref": "Protected"}},
                "OpenUrl": {"Value": {"Ref": "Open"}}},
})

_DENY_REPLACE = json.dumps({"Statement": [
    {"Effect": "Deny", "Action": "Update:Replace", "Principal": "*",
     "Resource": "LogicalResourceId/Protected"},
    {"Effect": "Allow", "Action": "Update:*", "Principal": "*", "Resource": "*"},
]})

_ALLOW_ALL = json.dumps({"Statement": [
    {"Effect": "Allow", "Action": "Update:*", "Principal": "*", "Resource": "*"},
]})


@tags("axis:rejection", "cap:c7", "concern:deploy", "concern:e2e", "plane:control")
def run(ctx) -> None:
    """A stack policy denying Update:Replace on one logical id stops that resource being
    replaced, rolls the whole update back, and the identical update succeeds once relaxed.
    """
    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")

    prot_v1 = _xname(ctx, "spol-v1") + "-prot"
    prot_v2 = _xname(ctx, "spol-v2") + "-prot"
    open_name = _xname(ctx, "spol") + "-open"
    for name in (prot_v1, prot_v2, open_name):
        ctx.on_cleanup(lambda n=name: _delete_queue_by_name_if_present(sqs, n))

    base = {"ProtectedName": prot_v1, "OpenName": open_name, "OpenTimeout": "30"}
    stack, status = _create_stack_and_wait(
        ctx, _TEMPLATE, stack_name=_xname(ctx, "spol"), parameters=base, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", f"setup stack ended in {status!r}"

    protected_before = _physical_id(cfn, stack, "Protected")
    open_url = _physical_id(cfn, stack, "Open")
    assert _visibility_timeout(sqs, open_url) == "30", (
        f"setup did not take: Open's VisibilityTimeout is "
        f"{_visibility_timeout(sqs, open_url)!r}, expected '30'"
    )

    cfn.set_stack_policy(StackName=stack, StackPolicyBody=_DENY_REPLACE)

    denied = {"ProtectedName": prot_v2, "OpenName": open_name, "OpenTimeout": "45"}
    before = len(_stack_events(cfn, stack))
    status = _update_stack_and_wait(ctx, stack, parameters=denied, timeout_s=900.0)
    assert status == "UPDATE_ROLLBACK_COMPLETE", (
        f"expected UPDATE_ROLLBACK_COMPLETE when the stack policy denies the replacement, got "
        f"{status!r}"
    )

    # 1. CloudFormation must attribute the failure to the stack policy, not to a bad template.
    protected_events = [(e["ResourceStatus"], e.get("ResourceStatusReason"))
                        for e in _stack_events(cfn, stack)[before:] if e["LogicalResourceId"] == "Protected"]
    assert protected_events == [
        ("UPDATE_FAILED", "Action denied by stack policy: Statement [#1] does not allow "
                          "[Update:Replace] for resource [LogicalResourceId/Protected];"),
        ("UPDATE_COMPLETE", "Resource skipped during UpdateRollback"),
    ], f"events of the protected queue: {protected_events!r}"

    # 2. The effect is ABSENT: the protected queue was never replaced.
    protected_after = _physical_id(cfn, stack, "Protected")
    assert protected_after == protected_before, (
        f"the protected queue was replaced despite the Deny: {protected_before!r} -> "
        f"{protected_after!r}"
    )
    assert _queue_url_or_none(sqs, prot_v2) is None, (
        f"a queue named {prot_v2!r} exists, so the denied replacement was partly performed"
    )

    # 3. And the rollback took the sibling's allowed in-place change back with it.
    assert _visibility_timeout(sqs, open_url) == "30", (
        f"the rollback left the unprotected sibling at "
        f"{_visibility_timeout(sqs, open_url)!r}; UPDATE_ROLLBACK_COMPLETE must restore '30'"
    )

    # Control: with the policy relaxed the identical update replaces the queue, proving the
    # first outcome was the policy and not an invalid template.
    cfn.set_stack_policy(StackName=stack, StackPolicyBody=_ALLOW_ALL)
    control_status = _update_stack_and_wait(ctx, stack, parameters=denied, timeout_s=900.0)
    assert control_status == "UPDATE_COMPLETE", (
        f"with the policy relaxed the identical update must succeed, got {control_status!r}"
    )
    control_protected = _physical_id(cfn, stack, "Protected")
    assert control_protected != protected_before, (
        f"the control kept physical id {control_protected!r}, so the update was never a "
        f"replacement and the first outcome proves nothing about the stack policy"
    )
    assert _visibility_timeout(sqs, _physical_id(cfn, stack, "Open")) == "45", (
        f"the control update did not apply the sibling's change either: "
        f"{_visibility_timeout(sqs, _physical_id(cfn, stack, 'Open'))!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_NO_SUCH_QUEUE = "AWS.SimpleQueueService.NonExistentQueue"

_CREATE_TERMINAL = {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
                    "DELETE_COMPLETE", "DELETE_FAILED"}

_UPDATE_TERMINAL = {"UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE",
                    "UPDATE_ROLLBACK_FAILED"}


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
    return cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]


def _physical_id(cfn, stack: str, logical_id: str) -> str:
    """The PhysicalResourceId CloudFormation currently records for a logical id."""
    return cfn.describe_stack_resource(
        StackName=stack, LogicalResourceId=logical_id)["StackResourceDetail"]["PhysicalResourceId"]


def _stack_events(cfn, name: str) -> list[dict[str, Any]]:
    """Every event for a stack, oldest first, paginated."""
    events: list[dict[str, Any]] = []
    token = None
    while True:
        kwargs: dict[str, Any] = {"StackName": name}
        if token:
            kwargs["NextToken"] = token
        page = cfn.describe_stack_events(**kwargs)
        events.extend(page.get("StackEvents", []))
        token = page.get("NextToken")
        if not token:
            break
    return list(reversed(events))


def _create_stack_and_wait(ctx, template: str, *, stack_name, parameters, timeout_s=900.0) -> tuple[str, str]:
    """create_stack, then poll to a terminal status which is RETURNED rather than asserted."""
    cfn = ctx.client("cloudformation")
    ctx.verify_account_safety()
    stack_id = cfn.create_stack(
        StackName=stack_name, TemplateBody=template, Tags=_tags_kv(),
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()],
    )["StackId"]
    ctx.on_cleanup(lambda: _teardown_stack(cfn, stack_id))
    status = _poll_until(lambda: _stack_status(cfn, stack_name), lambda s: s in _CREATE_TERMINAL,
                         timeout_s=timeout_s, interval_s=5.0,
                         description=f"create stack {stack_name}")
    return stack_name, status


def _update_stack_and_wait(ctx, name: str, *, parameters, timeout_s=900.0) -> str:
    """Update a stack on its previous template and poll to a terminal status, which is RETURNED."""
    cfn = ctx.client("cloudformation")
    cfn.update_stack(
        StackName=name, UsePreviousTemplate=True,
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()],
    )
    return _poll_until(lambda: _stack_status(cfn, name), lambda s: s in _UPDATE_TERMINAL,
                       timeout_s=timeout_s, interval_s=5.0,
                       description=f"update of stack {name}")


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
