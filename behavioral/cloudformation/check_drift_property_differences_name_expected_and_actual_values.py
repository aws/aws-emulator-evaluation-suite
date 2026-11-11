"""drift-property-differences-name-expected-and-actual-values."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "drift-property-differences-name-expected-and-actual-values"
GROUP = "state-machine"
SERVICES = ["cloudformation"]

STACK_TIMEOUT_S = 240.0
DETECT_TIMEOUT_S = 180.0
DETECT_ATTEMPTS = 4
PROPAGATE_TIMEOUT_S = 120.0
TEMPLATE_TIMEOUT = "45"
DRIFTED_TIMEOUT = "90"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Drift must report the exact property path, difference type and both the template and live
    values, and must leave an untouched sibling IN_SYNC in the same detection."""
    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")
    tag = [{"Key": "sim2real-check", "Value": CHECK}]

    stack = ctx.unique_name("sim2real-cfn-driftvals-")
    cfn.create_stack(StackName=stack, TemplateBody=_template(), Tags=tag)
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack))
    created = _poll_status(
        cfn, stack, {"CREATE_COMPLETE", "ROLLBACK_COMPLETE", "CREATE_FAILED"}, why="prerequisite create"
    )
    assert created == "CREATE_COMPLETE", f"stack {stack!r}: expected CREATE_COMPLETE, got {created!r}"

    drifted_url = _physical_id(cfn, stack, "Drifted")
    untouched_url = _physical_id(cfn, stack, "Untouched")

    # --- Beat 1: positive control — the detector must be able to say "no drift" ------------------
    # Without this, every assertion below also passes against a target that reports MODIFIED for
    # everything, always.
    clean = _detect(cfn, stack)
    assert clean["StackDriftStatus"] == "IN_SYNC", (
        f"a freshly created stack must detect as IN_SYNC, got {clean['StackDriftStatus']!r} "
        f"({clean.get('DriftedStackResourceCount')!r} drifted)"
    )
    clean_drifts = _drifts(cfn, stack)
    assert {d["StackResourceDriftStatus"] for d in clean_drifts.values()} == {"IN_SYNC"}, (
        f"every resource must start IN_SYNC, got "
        f"{ {k: v['StackResourceDriftStatus'] for k, v in clean_drifts.items()} !r}"
    )

    # --- Beat 2: change exactly one property, out of band, on exactly one resource ---------------
    sqs.set_queue_attributes(QueueUrl=drifted_url, Attributes={"VisibilityTimeout": DRIFTED_TIMEOUT})
    _await_attribute(sqs, drifted_url, "VisibilityTimeout", DRIFTED_TIMEOUT)

    # --- Beat 3: drift must name the path, the type, and BOTH values -----------------------------
    summary, drifts = _detect_until_modified(cfn, stack, "Drifted")
    drifted = drifts["Drifted"]
    untouched = drifts["Untouched"]

    assert drifted["StackResourceDriftStatus"] == "MODIFIED", (
        f"the out-of-band change must be reported MODIFIED, got "
        f"{drifted['StackResourceDriftStatus']!r}"
    )
    # Twin control in the same detection instant: an untouched resource of the same type must not be
    # dragged along.
    assert untouched["StackResourceDriftStatus"] == "IN_SYNC", (
        f"the untouched sibling queue {untouched_url!r} must stay IN_SYNC, got "
        f"{untouched['StackResourceDriftStatus']!r}"
    )

    diffs = drifted["PropertyDifferences"]
    assert len(diffs) == 1, (
        f"exactly one property was changed, so exactly one PropertyDifference is expected; got "
        f"{[(d.get('PropertyPath'), d.get('DifferenceType')) for d in diffs]!r}"
    )
    diff = diffs[0]
    assert diff["PropertyPath"] == "/VisibilityTimeout", (
        f"PropertyPath: expected '/VisibilityTimeout', got {diff['PropertyPath']!r}"
    )
    assert diff["DifferenceType"] == "NOT_EQUAL", (
        f"DifferenceType: expected 'NOT_EQUAL' for a changed scalar, got {diff['DifferenceType']!r}"
    )
    # Direction is pinned: expected is the template value, actual is the live resource value.
    assert str(diff["ExpectedValue"]) == TEMPLATE_TIMEOUT, (
        f"ExpectedValue must be the TEMPLATE value {TEMPLATE_TIMEOUT!r}, got {diff['ExpectedValue']!r}"
    )
    assert str(diff["ActualValue"]) == DRIFTED_TIMEOUT, (
        f"ActualValue must be the LIVE value {DRIFTED_TIMEOUT!r}, got {diff['ActualValue']!r}"
    )

    expected_props = json.loads(drifted["ExpectedProperties"])
    actual_props = json.loads(drifted["ActualProperties"])
    assert str(expected_props["VisibilityTimeout"]) == TEMPLATE_TIMEOUT, (
        f"ExpectedProperties.VisibilityTimeout: expected {TEMPLATE_TIMEOUT!r}, got "
        f"{expected_props.get('VisibilityTimeout')!r}"
    )
    assert str(actual_props["VisibilityTimeout"]) == DRIFTED_TIMEOUT, (
        f"ActualProperties.VisibilityTimeout: expected {DRIFTED_TIMEOUT!r}, got "
        f"{actual_props.get('VisibilityTimeout')!r}"
    )

    # --- Beat 4: the stack-level roll-up must agree with the resource-level detail ---------------
    # ``summary`` is the status record of the SAME detection whose per-resource detail was asserted
    # above, so the roll-up and the detail cannot be read from different runs.
    assert summary["StackDriftStatus"] == "DRIFTED", (
        f"stack drift status: expected DRIFTED, got {summary['StackDriftStatus']!r}"
    )
    assert summary["DriftedStackResourceCount"] == 1, (
        f"exactly one resource drifted, so DriftedStackResourceCount must be 1, got "
        f"{summary['DriftedStackResourceCount']!r}"
    )


def _template() -> str:
    """Two identical SQS queues; only one will be changed out of band."""
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Drifted": {
                    "Type": "AWS::SQS::Queue",
                    "Properties": {"VisibilityTimeout": int(TEMPLATE_TIMEOUT)},
                },
                "Untouched": {
                    "Type": "AWS::SQS::Queue",
                    "Properties": {"VisibilityTimeout": int(TEMPLATE_TIMEOUT)},
                },
            },
        }
    )


def _poll_status(cfn, stack_name: str, terminal: set[str], *, why: str) -> str:
    """Bounded retry with a deadline; RAISES on timeout rather than returning the last value."""
    deadline = time.monotonic() + STACK_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if last in terminal:
            return last
        time.sleep(4.0)
    raise AssertionError(
        f"stack {stack_name!r} did not reach any of {sorted(terminal)!r} within {STACK_TIMEOUT_S}s "
        f"[{why}] (last={last!r})"
    )


def _physical_id(cfn, stack_name: str, logical_id: str) -> str:
    detail = cfn.describe_stack_resource(StackName=stack_name, LogicalResourceId=logical_id)
    return detail["StackResourceDetail"]["PhysicalResourceId"]


def _await_attribute(sqs, queue_url: str, name: str, value: str) -> None:
    """SQS attribute writes are eventually consistent; drift detection started before the change is
    visible reports IN_SYNC. Bounded retry that RAISES on timeout."""
    deadline = time.monotonic() + PROPAGATE_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        last = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=[name])["Attributes"][name]
        if last == value:
            return
        time.sleep(3.0)
    raise AssertionError(
        f"queue {queue_url!r} attribute {name} never became {value!r} within {PROPAGATE_TIMEOUT_S}s "
        f"(last={last!r})"
    )


def _detect(cfn, stack_name: str) -> dict:
    """Run one drift detection to completion and return its status record. RAISES on timeout."""
    detection_id = cfn.detect_stack_drift(StackName=stack_name)["StackDriftDetectionId"]
    deadline = time.monotonic() + DETECT_TIMEOUT_S
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
        f"drift detection {detection_id!r} did not complete within {DETECT_TIMEOUT_S}s (last={last!r})"
    )


def _drifts(cfn, stack_name: str) -> dict:
    out = {}
    # botocore declares no paginator for this operation although the API returns NextToken, so
    # the token loop is written by hand; a first-page-only read would silently truncate.
    token = None
    while True:
        kw = {
            "StackName": stack_name,
            "StackResourceDriftStatusFilters": [
                "IN_SYNC",
                "MODIFIED",
                "DELETED",
                "NOT_CHECKED",
            ],
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


def _detect_until_modified(cfn, stack_name: str, logical_id: str) -> tuple[dict, dict]:
    """Re-run detection until the changed resource is MODIFIED; RAISES if it never is.

    Returns the status record and per-resource drifts of the SAME detection. Retried because the
    SQS change is eventually consistent from CloudFormation's point of view.
    """
    last: dict = {}
    for _ in range(DETECT_ATTEMPTS):
        summary = _detect(cfn, stack_name)
        last = _drifts(cfn, stack_name)
        if last.get(logical_id, {}).get("StackResourceDriftStatus") == "MODIFIED":
            return summary, last
        time.sleep(5.0)
    raise AssertionError(
        f"{logical_id!r} was never reported MODIFIED across {DETECT_ATTEMPTS} detections after its "
        f"VisibilityTimeout was changed out of band; last="
        f"{ {k: v['StackResourceDriftStatus'] for k, v in last.items()} !r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
