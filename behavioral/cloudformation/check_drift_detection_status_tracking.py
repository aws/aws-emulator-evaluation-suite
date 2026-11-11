"""drift-detection-status-tracking."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "drift-detection-status-tracking"
GROUP = "server-side"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """DetectStackDrift's async progress and terminal state are visible via DescribeStackDriftDetectionStatus."""
    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")
    stack_name = ctx.unique_name("sim2real-driftstatus-")

    template = {
        "Resources": {
            "DriftedQueue": {"Type": "AWS::SQS::Queue", "Properties": {"VisibilityTimeout": 30}},
            "CleanQueue": {"Type": "AWS::SQS::Queue", "Properties": {"VisibilityTimeout": 30}},
        }
    }
    stack_id = cfn.create_stack(StackName=stack_name, TemplateBody=json.dumps(template))["StackId"]
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_id))
    create_status = _wait_stack_terminal(cfn, stack_id)
    assert create_status == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, got {create_status}"

    drifted_url = cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId="DriftedQueue")[
        "StackResourceDetail"
    ]["PhysicalResourceId"]
    # cause real, out-of-band drift
    sqs.set_queue_attributes(QueueUrl=drifted_url, Attributes={"VisibilityTimeout": "90"})

    detection_id = cfn.detect_stack_drift(StackName=stack_id)["StackDriftDetectionId"]

    deadline = time.monotonic() + 180.0
    detection_status = None
    result = None
    while time.monotonic() < deadline:
        result = cfn.describe_stack_drift_detection_status(StackDriftDetectionId=detection_id)
        detection_status = result["DetectionStatus"]
        if detection_status != "DETECTION_IN_PROGRESS":
            break
        time.sleep(3)

    assert detection_status == "DETECTION_COMPLETE", f"drift detection did not complete: {result}"
    assert result["StackId"] == stack_id, f"expected StackId {stack_id}, got {result['StackId']}"
    assert result["StackDriftStatus"] == "DRIFTED", f"expected DRIFTED, got {result['StackDriftStatus']}"
    drifted_count = result.get("DriftedStackResourceCount", 0)
    assert drifted_count == 1, (
        f"only DriftedQueue was mutated out-of-band; CleanQueue should stay in sync, "
        f"so DriftedStackResourceCount should be exactly 1, got {drifted_count}"
    )


_TERMINAL = {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}


def _wait_stack_terminal(cfn, stack_name: str, timeout_s: float = 180.0, interval_s: float = 3.0) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        resp = cfn.describe_stacks(StackName=stack_name)
        stacks = resp.get("Stacks", [])
        if not stacks:
            return "DELETE_COMPLETE"
        status = stacks[0]["StackStatus"]
        if status in _TERMINAL:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not reach terminal status within {timeout_s}s (last={status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
