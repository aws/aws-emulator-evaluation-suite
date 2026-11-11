"""cfn-drift-reports-deleted-resource-and-drifted-stack-counts."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-drift-reports-deleted-resource-and-drifted-stack-counts"

GROUP = "drift"

SERVICES = ["cloudformation", "sqs"]

_TEMPLATE = json.dumps({
    "Parameters": {"DeletedName": {"Type": "String"}, "KeptName": {"Type": "String"}},
    "Resources": {
        "Deleted": {"Type": "AWS::SQS::Queue",
                    "Properties": {"QueueName": {"Ref": "DeletedName"},
                                   "VisibilityTimeout": 30}},
        "Kept": {"Type": "AWS::SQS::Queue",
                 "Properties": {"QueueName": {"Ref": "KeptName"}, "VisibilityTimeout": 30}},
    },
})


@tags("axis:happy-path", "cap:c3", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """Drift detection distinguishes a queue deleted out of band through SQS from an untouched
    sibling: DELETED vs IN_SYNC, a DRIFTED stack, and DriftedStackResourceCount of exactly 1.
    """
    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")

    deleted_name = _xname(ctx, "drift-q") + "-del"
    kept_name = _xname(ctx, "drift-q") + "-keep"
    for name in (deleted_name, kept_name):
        ctx.on_cleanup(lambda n=name: _delete_queue_by_name_if_present(sqs, n))

    stack, status = _create_stack_and_wait(
        ctx, _TEMPLATE, stack_name=_xname(ctx, "drift"),
        parameters={"DeletedName": deleted_name, "KeptName": kept_name}, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", f"setup stack ended in {status!r}"

    deleted_url = _physical_id(cfn, stack, "Deleted")

    sqs.delete_queue(QueueUrl=deleted_url)
    # SQS queue deletion is eventually consistent for up to 60 s, and drift detection started too
    # early reports IN_SYNC for a queue that is on its way out.
    _poll_for_error_code(lambda: sqs.get_queue_url(QueueName=deleted_name), _NO_SUCH_QUEUE,
                         f"get_queue_url {deleted_name} after delete_queue", timeout_s=180.0)
    _poll_until(lambda: _queue_names(sqs), lambda names: deleted_name not in names,
                timeout_s=180.0, interval_s=5.0,
                description=f"{deleted_name} gone from ListQueues")

    detection_id = cfn.detect_stack_drift(StackName=stack)["StackDriftDetectionId"]
    detection = _poll_until(
        lambda: cfn.describe_stack_drift_detection_status(StackDriftDetectionId=detection_id),
        lambda d: d["DetectionStatus"] != "DETECTION_IN_PROGRESS",
        timeout_s=600.0, interval_s=5.0, description=f"drift detection for {stack}")
    assert detection["DetectionStatus"] == "DETECTION_COMPLETE", (
        f"drift detection did not complete: {detection!r}"
    )

    drifts = {d["LogicalResourceId"]: d for d in _resource_drifts(cfn, stack)}
    assert set(drifts) == {"Deleted", "Kept"}, (
        f"drift must report on both resources, got {sorted(drifts)}"
    )
    assert drifts["Deleted"]["StackResourceDriftStatus"] == "DELETED", (
        f"a resource deleted out of band must be DELETED, got {drifts['Deleted']!r}"
    )
    assert drifts["Kept"]["StackResourceDriftStatus"] == "IN_SYNC", (
        f"the untouched sibling must stay IN_SYNC, got {drifts['Kept']!r}"
    )
    assert not drifts["Deleted"].get("PropertyDifferences"), (
        f"a DELETED resource has no property differences to report: {drifts['Deleted']!r}"
    )

    assert detection["StackDriftStatus"] == "DRIFTED", (
        f"one deleted resource must make the stack DRIFTED, got {detection!r}"
    )
    assert detection["DriftedStackResourceCount"] == 1, (
        f"expected exactly one drifted resource, got "
        f"{detection['DriftedStackResourceCount']!r} in {detection!r}"
    )

    # The stack's own drift record must agree with the detection's, not just the detection API.
    stack_drift = cfn.describe_stacks(StackName=stack)["Stacks"][0]["DriftInformation"]
    assert stack_drift["StackDriftStatus"] == "DRIFTED", (
        f"DescribeStacks still reports {stack_drift!r} after a completed detection"
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


def _poll_for_error_code(fn, code: str, description: str, *, timeout_s=180.0,
                         interval_s=5.0) -> None:
    """Poll fn() until it raises exactly `code`; a different code fails immediately."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
        except ClientError as exc:
            got = exc.response.get("Error", {}).get("Code", "")
            assert got == code, f"{description}: expected {code!r}, got {got!r} ({exc})"
            return
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description}: still succeeding after {timeout_s}s; expected {code!r}")
        time.sleep(interval_s)


def _queue_names(sqs) -> set[str]:
    """Every queue name in the account, paginated (the account may hold many queues)."""
    names: set[str] = set()
    for page in sqs.get_paginator("list_queues").paginate():
        for url in page.get("QueueUrls", []) or []:
            names.add(url.rsplit("/", 1)[-1])
    return names


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


def _stack_status(cfn, name: str) -> str:
    try:
        return cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
    except ClientError:
        return "GONE"


def _physical_id(cfn, stack: str, logical_id: str) -> str:
    """The PhysicalResourceId CloudFormation currently records for a logical id."""
    return cfn.describe_stack_resource(
        StackName=stack, LogicalResourceId=logical_id)["StackResourceDetail"]["PhysicalResourceId"]


def _resource_drifts(cfn, stack: str) -> list[dict[str, Any]]:
    """Every StackResourceDrift for a stack, paginated."""
    out: list[dict[str, Any]] = []
    token = None
    while True:
        kwargs: dict[str, Any] = {"StackName": stack}
        if token:
            kwargs["NextToken"] = token
        page = cfn.describe_stack_resource_drifts(**kwargs)
        out.extend(page.get("StackResourceDrifts", []))
        token = page.get("NextToken")
        if not token:
            return out


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
