"""drift-detection-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "drift-detection-lifecycle"
GROUP = "state-machine"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """Drift detection on stacks and individual resources transitions
    IN_PROGRESS->COMPLETE and surfaces per-resource drift status."""
    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")

    stack_name = ctx.unique_name("sim2real-drift-")
    # AWS::SNS::Topic's DisplayName is not reliably reported as drift by the real
    # drift-detection engine (many of its non-Tag properties are excluded from drift
    # comparison). AWS::SQS::Queue's VisibilityTimeout is the property AWS's own
    # drift-detection documentation/tutorial uses to demonstrate MODIFIED drift, so use
    # that here for a resource/property pair that reliably participates in drift checks.
    # Crucially, the property must be explicitly set IN THE TEMPLATE: CloudFormation's
    # drift engine only compares properties that were part of the template's expected
    # configuration, so an unset property (falling back to the service-side default)
    # never registers as MODIFIED no matter how it's mutated out-of-band afterward.
    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {"Queue": {"Type": "AWS::SQS::Queue", "Properties": {"VisibilityTimeout": 30}}},
        }
    )
    cfn.create_stack(StackName=stack_name, TemplateBody=template)
    ctx.on_cleanup(lambda: _safe_delete_stack(cfn, stack_name))
    _wait_stack_status(cfn, stack_name, {"CREATE_COMPLETE"}, timeout_s=180)

    queue_url = cfn.describe_stack_resource(StackName=stack_name, LogicalResourceId="Queue")[
        "StackResourceDetail"
    ]["PhysicalResourceId"]

    # Mutate the resource out-of-band so the stack drifts from its template.
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"VisibilityTimeout": "120"})
    _poll_until(
        lambda: sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["VisibilityTimeout"])["Attributes"].get(
            "VisibilityTimeout"
        ),
        lambda v: v == "120",
        timeout_s=60,
        interval_s=3,
    )

    detection_id = cfn.detect_stack_drift(StackName=stack_name)["StackDriftDetectionId"]

    def _detection_status():
        return cfn.describe_stack_drift_detection_status(StackDriftDetectionId=detection_id)

    status = _poll_until(
        _detection_status, lambda r: r["DetectionStatus"] in ("DETECTION_COMPLETE", "DETECTION_FAILED"), timeout_s=180, interval_s=5
    )
    assert status["DetectionStatus"] == "DETECTION_COMPLETE", status

    # The drift engine reads a fresh snapshot of the resource on each detection
    # run; if it raced the SQS attribute propagation and reported IN_SYNC once,
    # re-running detection (now that the attribute change is confirmed above)
    # should reliably surface DRIFTED.
    retries_left = 3
    while status["StackDriftStatus"] != "DRIFTED" and retries_left > 0:
        retries_left -= 1
        detection_id = cfn.detect_stack_drift(StackName=stack_name)["StackDriftDetectionId"]
        status = _poll_until(
            _detection_status,
            lambda r: r["DetectionStatus"] in ("DETECTION_COMPLETE", "DETECTION_FAILED"),
            timeout_s=180,
            interval_s=5,
        )
        assert status["DetectionStatus"] == "DETECTION_COMPLETE", status
    assert status["StackDriftStatus"] == "DRIFTED", status

    drifts = cfn.describe_stack_resource_drifts(StackName=stack_name)["StackResourceDrifts"]
    queue_drift = next(d for d in drifts if d["LogicalResourceId"] == "Queue")
    assert queue_drift["StackResourceDriftStatus"] == "MODIFIED", queue_drift
    prop_paths = {p["PropertyPath"] for p in queue_drift.get("PropertyDifferences", [])}
    assert "/VisibilityTimeout" in prop_paths, queue_drift

    single = cfn.detect_stack_resource_drift(StackName=stack_name, LogicalResourceId="Queue")["StackResourceDrift"]
    assert single["StackResourceDriftStatus"] == "MODIFIED", single


def _safe_delete_stack(cfn, stack_name) -> None:
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise


def _wait_stack_status(cfn, stack_name, terminal_statuses, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    while True:
        status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if status in terminal_statuses:
            return status
        if time.monotonic() >= deadline:
            raise AssertionError(f"stack {stack_name} did not reach {terminal_statuses}, last={status}")
        time.sleep(interval_s)


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s; last value={result!r}")
        time.sleep(interval_s)
        result = probe()
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
