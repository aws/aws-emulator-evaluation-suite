"""drift-detection-async-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "drift-detection-async-lifecycle"
GROUP = 'drift'
SERVICES = ['cloudformation']


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """DetectStackDrift is asynchronous: the detection id progresses to DETECTION_COMPLETE and
    an untouched stack is IN_SYNC."""
    cfn = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-behav-cfn-drift-")
    tmpl = _sns_topic_template(ctx.unique_name("sim2real-behav-cfn-topic-"))
    cfn.create_stack(StackName=name, TemplateBody=tmpl)
    ctx.on_cleanup(lambda: _delete_stack_quiet(cfn, name))
    stack = _wait_stack_status(cfn, name)

    # before any detection has run the stack reports NOT_CHECKED
    assert stack["DriftInformation"]["StackDriftStatus"] == "NOT_CHECKED", stack["DriftInformation"]

    detection_id = cfn.detect_stack_drift(StackName=name)["StackDriftDetectionId"]
    assert detection_id, "DetectStackDrift did not return a StackDriftDetectionId"

    result = _wait_drift_detection(cfn, detection_id, timeout_s=300)
    assert result["DetectionStatus"] == "DETECTION_COMPLETE", result
    assert result["StackDriftStatus"] == "IN_SYNC", result["StackDriftStatus"]
    assert result["StackId"] == stack["StackId"], (result["StackId"], stack["StackId"])

    drifts = cfn.describe_stack_resource_drifts(StackName=name)["StackResourceDrifts"]
    assert len(drifts) == 1, drifts
    assert drifts[0]["StackResourceDriftStatus"] == "IN_SYNC", drifts[0]

    after = _describe_stack(cfn, name)
    assert after["DriftInformation"]["StackDriftStatus"] == "IN_SYNC", after["DriftInformation"]


_TERMINAL_STACK_STATUSES = {
    "CREATE_COMPLETE",
    "CREATE_FAILED",
    "ROLLBACK_COMPLETE",
    "ROLLBACK_FAILED",
    "UPDATE_COMPLETE",
    "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_ROLLBACK_FAILED",
    "DELETE_COMPLETE",
    "DELETE_FAILED",
}


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _sns_topic_template(topic_name, display_name=None) -> str:
    props = {"TopicName": topic_name}
    if display_name is not None:
        props["DisplayName"] = display_name
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {"MyTopic": {"Type": "AWS::SNS::Topic", "Properties": props}},
            "Outputs": {"TopicArnOutput": {"Value": {"Ref": "MyTopic"}}},
        }
    )


def _describe_stack(cfn, name):
    stacks = cfn.describe_stacks(StackName=name).get("Stacks", [])
    assert stacks, f"stack {name} not found"
    return stacks[0]


def _wait_stack_status(cfn, name, timeout_s=180, interval_s=3):
    """Poll DescribeStacks until the stack reaches any terminal status."""
    return _poll_until(
        lambda: _describe_stack(cfn, name),
        lambda stack: stack.get("StackStatus") in _TERMINAL_STACK_STATUSES,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"stack {name} reaching a terminal status",
    )


def _wait_drift_detection(cfn, detection_id, timeout_s=180, interval_s=4):
    return _poll_until(
        lambda: cfn.describe_stack_drift_detection_status(StackDriftDetectionId=detection_id),
        lambda resp: resp.get("DetectionStatus") in {"DETECTION_COMPLETE", "DETECTION_FAILED"},
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"drift detection {detection_id} completing",
    )


def _delete_stack_quiet(cfn, name):
    try:
        cfn.delete_stack(StackName=name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
