"""cfn-resource-import-with-mismatched-visibility-timeout-reconciles-live-value-to-template."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-resource-import-with-mismatched-visibility-timeout-reconciles-live-value-to-template"

GROUP = "deploy_import"

SERVICES = ["cloudformation", "sqs"]

_LIVE_TIMEOUT = "30"
_TEMPLATE_TIMEOUT = "90"
_OOB_TIMEOUT = "45"


def _template(queue_name: str) -> str:
    """An IMPORT template whose VisibilityTimeout (90) differs from the live queue's (30).
    DeletionPolicy Retain is required by the IMPORT change set.
    """
    return json.dumps({
        "Resources": {
            "Imported": {
                "Type": "AWS::SQS::Queue",
                "DeletionPolicy": "Retain",
                "Properties": {"QueueName": queue_name,
                                "VisibilityTimeout": int(_TEMPLATE_TIMEOUT)},
            },
        },
    })


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Importing a queue whose template VisibilityTimeout differs from the live value completes
    IMPORT_COMPLETE, but the import overwrites the live property to the template's value rather
    than leaving it as found, so drift detection reports IN_SYNC right afterward.
    """
    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")

    queue_name = _xname(ctx, "imp-recon")
    queue_url = sqs.create_queue(
        QueueName=queue_name,
        Attributes={"VisibilityTimeout": _LIVE_TIMEOUT},
        tags={"sim2real": "cfn-resource-import-reconcile"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_queue_by_name_if_present(sqs, queue_name))

    stack = _xname(ctx, "imp-recon-s")
    change_set = cfn.create_change_set(
        StackName=stack,
        ChangeSetName=_xname(ctx, "imp-recon-cs"),
        ChangeSetType="IMPORT",
        TemplateBody=_template(queue_name),
        ResourcesToImport=[{
            "ResourceType": "AWS::SQS::Queue",
            "LogicalResourceId": "Imported",
            "ResourceIdentifier": {"QueueUrl": queue_url},
        }],
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    )["Id"]
    # An IMPORT change set CREATES the stack (in REVIEW_IN_PROGRESS), so the stack teardown is
    # registered here rather than after any create_stack.
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, stack, timeout_s=600.0))

    cs_status = _poll_until(lambda: _change_set(cfn, change_set)["Status"],
                            lambda s: s in {"CREATE_COMPLETE", "FAILED"},
                            timeout_s=300.0, interval_s=3.0,
                            description=f"IMPORT change set for {stack}")
    described = _change_set(cfn, change_set)
    assert cs_status == "CREATE_COMPLETE", (
        f"the IMPORT change set ended {cs_status!r}: {described.get('StatusReason')!r}"
    )
    changes = described["Changes"]
    assert len(changes) == 1, f"expected one change, got {changes!r}"
    assert changes[0]["ResourceChange"]["Action"] == "Import", (
        f"an IMPORT change set must describe its resource as Action Import even though its "
        f"VisibilityTimeout mismatches the live queue, got {changes[0]!r}"
    )

    cfn.execute_change_set(ChangeSetName=change_set)
    status = _poll_until(lambda: _stack_status(cfn, stack),
                         lambda s: s in {"IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
                                         "IMPORT_ROLLBACK_FAILED", "ROLLBACK_COMPLETE", "GONE"},
                         timeout_s=900.0, interval_s=5.0, description=f"import into {stack}")
    assert status == "IMPORT_COMPLETE", (
        f"an import whose template VisibilityTimeout mismatches the live value must still "
        f"complete, got {status!r}"
    )

    # 1. The import action is labelled "Import", not "Modify", yet executing it reconciles the
    #    live property to the template's value rather than leaving the queue as it was found.
    #    The poll fails unless the live value reads the template's, not the pre-import one.
    _await_timeout(sqs, queue_url, _TEMPLATE_TIMEOUT)

    # 2. Because the live value now equals the template value, a freshly imported resource that
    #    arrived mismatched is IN_SYNC, not MODIFIED.
    clean = _detect(cfn, stack)
    assert clean["StackDriftStatus"] == "IN_SYNC", (
        f"the live value was reconciled to the template during import, so drift must report "
        f"IN_SYNC, got {clean['StackDriftStatus']!r}"
    )
    clean_drifts = _drifts(cfn, stack)
    assert clean_drifts["Imported"]["StackResourceDriftStatus"] == "IN_SYNC", (
        f"expected the imported resource IN_SYNC right after import, got "
        f"{clean_drifts['Imported']['StackResourceDriftStatus']!r}"
    )

    # 3. Positive control: drift detection is not merely reporting IN_SYNC unconditionally — a
    #    genuine out-of-band change away from that same template value is still caught.
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"VisibilityTimeout": _OOB_TIMEOUT})
    _await_timeout(sqs, queue_url, _OOB_TIMEOUT)

    summary, drifts = _detect_until_modified(cfn, stack, "Imported")
    drifted = drifts["Imported"]
    diffs = drifted["PropertyDifferences"]
    assert len(diffs) == 1, (
        f"only VisibilityTimeout was changed out of band, so exactly one PropertyDifference is "
        f"expected; got {[(d.get('PropertyPath'), d.get('DifferenceType')) for d in diffs]!r}"
    )
    diff = diffs[0]
    assert diff["PropertyPath"] == "/VisibilityTimeout", (
        f"PropertyPath: expected '/VisibilityTimeout', got {diff['PropertyPath']!r}"
    )
    assert diff["DifferenceType"] == "NOT_EQUAL", (
        f"DifferenceType: expected 'NOT_EQUAL' for a changed scalar, got {diff['DifferenceType']!r}"
    )
    assert str(diff["ExpectedValue"]) == _TEMPLATE_TIMEOUT, (
        f"ExpectedValue must still be the TEMPLATE value {_TEMPLATE_TIMEOUT!r}, got "
        f"{diff['ExpectedValue']!r}"
    )
    assert str(diff["ActualValue"]) == _OOB_TIMEOUT, (
        f"ActualValue must be the out-of-band LIVE value {_OOB_TIMEOUT!r}, got "
        f"{diff['ActualValue']!r}"
    )
    assert summary["StackDriftStatus"] == "DRIFTED", (
        f"stack drift status: expected DRIFTED, got {summary['StackDriftStatus']!r}"
    )
    assert summary["DriftedStackResourceCount"] == 1, (
        f"exactly one resource drifted, so DriftedStackResourceCount must be 1, got "
        f"{summary['DriftedStackResourceCount']!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_NO_SUCH_QUEUE = "AWS.SimpleQueueService.NonExistentQueue"

_DETECT_DEADLINE_S = 300.0


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


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


def _await_timeout(sqs, queue_url: str, value: str, *, timeout_s: float = 120.0) -> str:
    """SQS attribute writes are eventually consistent; poll until the read matches ``value``."""
    return _poll_until(
        lambda: sqs.get_queue_attributes(
            QueueUrl=queue_url, AttributeNames=["VisibilityTimeout"]
        )["Attributes"]["VisibilityTimeout"],
        lambda v: v == value, timeout_s=timeout_s, interval_s=3.0,
        description=f"VisibilityTimeout on {queue_url} to read {value!r}")


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
    """The stack's status, or "GONE" when DescribeStacks reports exactly that it does not exist."""
    try:
        return cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        err = exc.response["Error"]
        if (err.get("Code"), err.get("Message")) == ("ValidationError", f"Stack with id {name} does not exist"):
            return "GONE"
        raise


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


def _detect(cfn, stack_name: str, *, timeout_s: float = 180.0) -> dict[str, Any]:
    """Run one drift detection to completion and return its status record. Raises on timeout."""
    detection_id = cfn.detect_stack_drift(StackName=stack_name)["StackDriftDetectionId"]
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stack_drift_detection_status(StackDriftDetectionId=detection_id)
        if last["DetectionStatus"] in {"DETECTION_COMPLETE", "DETECTION_FAILED"}:
            assert last["DetectionStatus"] == "DETECTION_COMPLETE", (
                f"drift detection {detection_id!r} failed: {last.get('DetectionStatusReason')!r}"
            )
            return last
        time.sleep(3.0)
    raise AssertionError(
        f"drift detection {detection_id!r} did not complete within {timeout_s}s (last={last!r})"
    )


def _drifts(cfn, stack_name: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    token = None
    while True:
        kw: dict[str, Any] = {
            "StackName": stack_name,
            "StackResourceDriftStatusFilters": ["IN_SYNC", "MODIFIED", "DELETED", "NOT_CHECKED"],
        }
        if token:
            kw["NextToken"] = token
        page = cfn.describe_stack_resource_drifts(**kw)
        for drift in page["StackResourceDrifts"]:
            out[drift["LogicalResourceId"]] = drift
        token = page.get("NextToken")
        if not token:
            break
    return out


def _detect_until_modified(
    cfn, stack_name: str, logical_id: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Re-run detection until ``logical_id`` is reported MODIFIED, against a clock deadline;
    raises if it never is. Returns the status record and per-resource drifts of the SAME detection.
    """
    deadline = time.monotonic() + _DETECT_DEADLINE_S
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        summary = _detect(cfn, stack_name)
        last = _drifts(cfn, stack_name)
        if last.get(logical_id, {}).get("StackResourceDriftStatus") == "MODIFIED":
            return summary, last
        time.sleep(5.0)
    raise AssertionError(
        f"{logical_id!r} was never reported MODIFIED within {_DETECT_DEADLINE_S}s; last="
        f"{ {k: v['StackResourceDriftStatus'] for k, v in last.items()} !r}"
    )


def _delete_stack_and_wait(ctx, name: str, *, timeout_s=900.0) -> None:
    """Delete a stack and wait for it to go; DELETE_FAILED or a timeout raises."""
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=name)
    final = _poll_until(lambda: _stack_status(cfn, name),
                        lambda s: s in {"DELETE_COMPLETE", "GONE", "DELETE_FAILED"},
                        timeout_s=timeout_s, interval_s=5.0,
                        description=f"delete stack {name}")
    if final == "DELETE_FAILED":
        raise RuntimeError(f"stack {name} ended DELETE_FAILED; its resources are stranded")

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
