"""cfn-on-failure-do-nothing-preserves-partial-resources-that-still-work."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-on-failure-do-nothing-preserves-partial-resources-that-still-work"

GROUP = "deploy_rollback"

SERVICES = ["cloudformation", "sqs"]


def _template(keep_name: str, doomed_name: str) -> str:
    """A queue that must succeed, then a FIFO queue whose name has no .fifo suffix.

    The ordering is pinned with DependsOn so the survivable resource is genuinely created
    BEFORE the failure: without it CloudFormation may create both concurrently and there is no
    "already created" resource for OnFailure to decide the fate of. The FIFO name violation is
    rejected by SQS at CreateQueue, i.e. during CREATE -- a template *syntax* error would be
    rejected by ValidateTemplate and the stack would never reach CREATE_FAILED at all.
    """
    return json.dumps({
        "Resources": {
            "Keep": {
                "Type": "AWS::SQS::Queue",
                "Properties": {"QueueName": keep_name, "VisibilityTimeout": 30},
            },
            "Doomed": {
                "Type": "AWS::SQS::Queue",
                "DependsOn": "Keep",
                "Properties": {"QueueName": doomed_name, "FifoQueue": True},
            },
        },
        "Outputs": {"KeepUrl": {"Value": {"Ref": "Keep"}}},
    })


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e",
      "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """With OnFailure=DO_NOTHING a stack whose later resource fails stays CREATE_FAILED and the
    queue it created first remains and delivers a message; with OnFailure=DELETE the same template
    leaves no queue, which SQS reports as "The specified queue does not exist."."""
    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")

    keep_do = _xname(ctx, "onfail-q") + "-keep"
    doomed_do = _xname(ctx, "onfail-q") + "-doomed"
    keep_del = _xname(ctx, "onfail-q") + "-keep"
    doomed_del = _xname(ctx, "onfail-q") + "-doomed"
    # Registered BEFORE either create_stack so LIFO runs them last: a CREATE_FAILED stack does
    # not always track a resource it created before the failure, so the by-name delete is the
    # only handle that certainly reaches the queue.
    for name in (keep_do, doomed_do, keep_del, doomed_del):
        ctx.on_cleanup(lambda n=name: _delete_queue_by_name_if_present(sqs, n))

    # ---- OnFailure=DO_NOTHING: the stack stops where it broke ----
    stack_do, status = _create_stack_and_wait(
        ctx, _template(keep_do, doomed_do),
        stack_name=_xname(ctx, "onfail-do"), on_failure="DO_NOTHING", timeout_s=600.0,
    )
    assert status == "CREATE_FAILED", (
        f"expected CREATE_FAILED with OnFailure=DO_NOTHING, got {status!r}; DO_NOTHING must "
        f"leave the stack standing at the point of failure rather than rolling it back"
    )

    reason = _resource_reason(cfn, stack_do, "Doomed", "CREATE_FAILED")
    assert "fifo" in reason.lower(), (
        f"the stack event must name why the second resource failed (the missing .fifo suffix); "
        f"got {reason!r}"
    )

    resources = {r["LogicalResourceId"]: r for r in
                 _stack_resources(cfn, stack_do)}
    queue_url = resources.get("Keep", {}).get("PhysicalResourceId")
    assert queue_url, (
        f"the queue created before the failure must survive DO_NOTHING; the stack's resources "
        f"were {resources!r}"
    )

    # The survivor is not merely listed: it works.
    marker = f"onfailure-do-nothing-{keep_do}"
    sqs.send_message(QueueUrl=queue_url, MessageBody=marker)
    received = _receive_one(sqs, queue_url, timeout_s=120.0)
    assert received["Body"] == marker, (
        f"the surviving queue is present but not functional: {received!r}"
    )

    # ---- Control: OnFailure=DELETE on the identical template must leave no queue ----
    stack_del, control_status = _create_stack_and_wait(
        ctx, _template(keep_del, doomed_del),
        stack_name=_xname(ctx, "onfail-del"), on_failure="DELETE", timeout_s=600.0,
    )
    assert control_status == "GONE", (
        f"OnFailure=DELETE must remove the whole stack after the failure; DescribeStacks still "
        f"reports {control_status!r} for {stack_del!r}"
    )
    control_code, control_message = _error_code(lambda: sqs.get_queue_url(QueueName=keep_del))
    assert control_code == _NO_SUCH_QUEUE, (
        f"OnFailure=DELETE must remove the partially created queue {keep_del!r}, but "
        f"GetQueueUrl reported {control_code!r}"
    )
    assert control_message == "The specified queue does not exist.", (
        f"expected the exact AWS.SimpleQueueService.NonExistentQueue message AWS returns, got {control_message!r}"
    )

    # And the two modes really did differ on the SAME template: the DO_NOTHING survivor is
    # still there after the control run proved DELETE removes it.
    assert _queue_url_or_none(sqs, keep_do) == queue_url, (
        f"the DO_NOTHING queue {keep_do!r} vanished; without it the control proves nothing "
        f"about OnFailure and only that the queue was never created"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_NO_SUCH_QUEUE = "AWS.SimpleQueueService.NonExistentQueue"

_CREATE_TERMINAL = {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
                    "DELETE_COMPLETE", "DELETE_FAILED", "GONE"}


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


def _error_code(fn) -> tuple[str, str]:
    """The AWS error code and message fn() raises. RAISES if fn() unexpectedly SUCCEEDS.

    Not a falsy sentinel on success: a target that accepts input AWS rejects fails on that,
    not on an error-code mismatch.
    """
    try:
        ok = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code", ""), exc.response.get("Error", {}).get("Message", "")
    raise AssertionError(f"expected this call to fail, but it succeeded and returned {ok!r}")


def _queue_url_or_none(sqs, name: str) -> str | None:
    try:
        return sqs.get_queue_url(QueueName=name)["QueueUrl"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == _NO_SUCH_QUEUE:
            return None
        raise


def _delete_queue_by_name_if_present(sqs, name: str) -> None:
    """Queue teardown by name; a queue already gone is not an error."""
    url = _queue_url_or_none(sqs, name)
    if url:
        sqs.delete_queue(QueueUrl=url)


def _receive_one(sqs, url: str, *, timeout_s=120.0) -> dict[str, Any]:
    """Long-poll a queue until one message arrives; return it (raises on timeout)."""
    msgs = _poll_until(
        lambda: sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1,
                                    WaitTimeSeconds=20).get("Messages", []),
        bool, timeout_s=timeout_s, interval_s=1.0, description=f"a message on {url}")
    return msgs[0]


def _stack_status(cfn, name: str) -> str:
    try:
        return cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
    except ClientError:
        return "GONE"


def _stack_resources(cfn, name: str) -> list[dict[str, Any]]:
    """Every resource CloudFormation currently records for a stack, paginated."""
    out: list[dict[str, Any]] = []
    token = None
    while True:
        kwargs: dict[str, Any] = {"StackName": name}
        if token:
            kwargs["NextToken"] = token
        page = cfn.list_stack_resources(**kwargs)
        out.extend(page.get("StackResourceSummaries", []))
        token = page.get("NextToken")
        if not token:
            return out


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


def _resource_reason(cfn, stack: str, logical_id: str, status: str) -> str:
    """The ResourceStatusReason CloudFormation recorded for one resource reaching `status`."""
    hits = [e for e in _stack_events(cfn, stack)
            if e.get("LogicalResourceId") == logical_id and e.get("ResourceStatus") == status]
    assert hits, (
        f"no {status} event for logical id {logical_id!r} in stack {stack!r}; events were "
        f"{[(e.get('LogicalResourceId'), e.get('ResourceStatus')) for e in _stack_events(cfn, stack)]!r}"
    )
    return hits[-1].get("ResourceStatusReason") or ""


def _delete_stack_and_wait(ctx, name: str, *, timeout_s=900.0) -> None:
    """Delete a stack and wait for it to go; DELETE_FAILED or any error other than not-found
    raises, so a stack that will not delete fails the teardown."""
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
                           capabilities=None, on_failure=None, rollback_configuration=None,
                           timeout_s=900.0) -> tuple[str, str]:
    """create_stack, then poll to a terminal status which is RETURNED rather than asserted.

    A CREATE that FAILS is the behaviour under test here, so the caller decides which terminal
    status is correct. The delete_stack teardown is registered immediately after create_stack,
    before anything is polled or asserted.
    """
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
    if on_failure:
        kwargs["OnFailure"] = on_failure
    if rollback_configuration is not None:
        kwargs["RollbackConfiguration"] = rollback_configuration
    cfn.create_stack(**kwargs)
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name, timeout_s=timeout_s))
    status = _poll_until(lambda: _stack_status(cfn, name), lambda s: s in _CREATE_TERMINAL,
                         timeout_s=timeout_s, interval_s=5.0,
                         description=f"create stack {name}")
    return name, status


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
