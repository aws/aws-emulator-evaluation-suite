"""detect-stack-resource-drift-single."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "detect-stack-resource-drift-single"
GROUP = "server-side"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """DetectStackResourceDrift returns a per-resource drift status without any full-stack detection."""
    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")
    stack_name = ctx.unique_name("sim2real-resdrift-")

    template = {
        "Resources": {
            "DriftedQueue": {"Type": "AWS::SQS::Queue", "Properties": {"VisibilityTimeout": 30}},
            "CleanQueue": {"Type": "AWS::SQS::Queue", "Properties": {"VisibilityTimeout": 30}},
        }
    }
    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["StackId"]
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_id))
    stack_status = _wait_stack_terminal(cfn, stack_id)
    assert stack_status == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, got {stack_status}"

    drifted_url = cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId="DriftedQueue")[
        "StackResourceDetail"
    ]["PhysicalResourceId"]
    sqs.set_queue_attributes(QueueUrl=drifted_url, Attributes={"VisibilityTimeout": "120"})
    # AWS::SQS::Queue attribute writes are eventually consistent; DetectStackResourceDrift reads
    # a live snapshot of the resource, so it can race the propagation and report IN_SYNC for a
    # resource that has, in fact, already changed. Confirm the read side before detecting.
    _poll_until(
        lambda: sqs.get_queue_attributes(QueueUrl=drifted_url, AttributeNames=["VisibilityTimeout"])[
            "Attributes"
        ].get("VisibilityTimeout"),
        lambda v: v == "120",
        timeout_s=60,
        interval_s=3,
    )

    # NOTE: no DetectStackDrift / DescribeStackDriftDetectionStatus call anywhere in this check -
    # DetectStackResourceDrift must work standalone, per resource.
    clean_result = cfn.detect_stack_resource_drift(StackName=stack_id, LogicalResourceId="CleanQueue")
    clean_status = clean_result["StackResourceDrift"]["StackResourceDriftStatus"]
    assert clean_status == "IN_SYNC", f"expected IN_SYNC for CleanQueue, got {clean_status}"

    drifted_result = cfn.detect_stack_resource_drift(StackName=stack_id, LogicalResourceId="DriftedQueue")
    drift = drifted_result["StackResourceDrift"]
    assert drift["StackResourceDriftStatus"] == "MODIFIED", f"expected MODIFIED, got {drift}"
    prop_diffs = drift.get("PropertyDifferences", [])
    assert any(d["PropertyPath"] == "/VisibilityTimeout" for d in prop_diffs), prop_diffs


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


def _poll_until(probe, predicate, *, timeout_s: float = 120.0, interval_s: float = 3.0):
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
