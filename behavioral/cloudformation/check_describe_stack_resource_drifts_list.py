"""describe-stack-resource-drifts-list."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-stack-resource-drifts-list"
GROUP = "server-side"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """After drift detection, DescribeStackResourceDrifts with a non-IN_SYNC filter excludes clean resources."""
    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")
    stack_name = ctx.unique_name("sim2real-listdrifts-")

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
    sqs.set_queue_attributes(QueueUrl=drifted_url, Attributes={"VisibilityTimeout": "77"})

    detection_id = cfn.detect_stack_drift(StackName=stack_id)["StackDriftDetectionId"]
    deadline = time.monotonic() + 180.0
    detection_status = None
    while time.monotonic() < deadline:
        detection_status = cfn.describe_stack_drift_detection_status(StackDriftDetectionId=detection_id)[
            "DetectionStatus"
        ]
        if detection_status != "DETECTION_IN_PROGRESS":
            break
        time.sleep(3)
    assert detection_status == "DETECTION_COMPLETE", f"drift detection did not complete: {detection_status}"

    non_in_sync = cfn.describe_stack_resource_drifts(
        StackName=stack_id, StackResourceDriftStatusFilters=["MODIFIED", "DELETED"]
    )["StackResourceDrifts"]
    logical_ids = {d["LogicalResourceId"] for d in non_in_sync}
    assert logical_ids == {"DriftedQueue"}, f"filtered list should only contain DriftedQueue, got {logical_ids}"

    in_sync_only = cfn.describe_stack_resource_drifts(
        StackName=stack_id, StackResourceDriftStatusFilters=["IN_SYNC"]
    )["StackResourceDrifts"]
    in_sync_ids = {d["LogicalResourceId"] for d in in_sync_only}
    assert in_sync_ids == {"CleanQueue"}, f"IN_SYNC filter should only contain CleanQueue, got {in_sync_ids}"

    # The check already tears the stack down (via ctx.on_cleanup below); prove that delete
    # actually took effect instead of leaving it unasserted. Deleted-by-name lookups fail
    # immediately with the stack-not-found flavor of ValidationError (deleted-by-id lookups
    # keep answering for a while, which is why the not-found read below uses stack_name).
    cfn.delete_stack(StackName=stack_name)
    delete_error = _wait_stack_deleted(cfn, stack_name)
    delete_code = delete_error.response["Error"]["Code"]
    delete_message = delete_error.response["Error"].get("Message", "")
    assert delete_code == "ValidationError", f"expected ValidationError after delete, got {delete_code!r}"
    expected_delete_message = f"Stack with id {stack_name} does not exist"
    assert delete_message == expected_delete_message, (
        f"expected {expected_delete_message!r}, got {delete_message!r}"
    )

    drift_error = _expect_error(
        lambda: cfn.describe_stack_resource_drifts(StackName=stack_name, StackResourceDriftStatusFilters=["MODIFIED"])
    )
    drift_code = drift_error.response["Error"]["Code"]
    drift_message = drift_error.response["Error"].get("Message", "")
    assert drift_code == "ValidationError", f"expected ValidationError, got {drift_code!r}: {drift_message}"
    expected_drift_message = f"Stack [{stack_name}] does not exist"
    assert drift_message == expected_drift_message, (
        f"expected {expected_drift_message!r}, got {drift_message!r}"
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


def _expect_error(fn):
    """Call fn(); return the raised ClientError. Raise if fn() succeeds unexpectedly."""
    try:
        result = fn()
    except ClientError as exc:
        return exc
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _wait_stack_deleted(cfn, stack_name: str, timeout_s: float = 180.0, interval_s: float = 3.0):
    """Poll DescribeStacks by name until it raises the stack-not-found ValidationError; return it."""
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        try:
            stacks = cfn.describe_stacks(StackName=stack_name).get("Stacks", [])
        except ClientError as exc:
            return exc
        last_status = stacks[0]["StackStatus"] if stacks else None
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not reach deleted within {timeout_s}s (last={last_status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
