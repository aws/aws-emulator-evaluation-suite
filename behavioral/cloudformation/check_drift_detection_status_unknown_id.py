"""drift-detection-status-unknown-id."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "drift-detection-status-unknown-id"
GROUP = 'drift'
SERVICES = ['cloudformation']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeStackDriftDetectionStatus with an unknown detection id raises ValidationError, while a
    real detection id from DetectStackDrift reports DETECTION_COMPLETE for its stack."""
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-drift-unknown-id-")

    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps({"Resources": {"Topic": {"Type": "AWS::SNS::Topic"}}}),
    )["StackId"]
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_name))
    _wait_stack_status(cfn, stack_name, {"CREATE_COMPLETE"})

    detection_id = cfn.detect_stack_drift(StackName=stack_name)["StackDriftDetectionId"]
    status = _poll_until(
        lambda: cfn.describe_stack_drift_detection_status(StackDriftDetectionId=detection_id),
        lambda r: r["DetectionStatus"] in ("DETECTION_COMPLETE", "DETECTION_FAILED"),
        timeout_s=180,
        interval_s=5,
    )
    assert status["DetectionStatus"] == "DETECTION_COMPLETE", (
        f"positive control: drift detection on a real stack did not complete: {status}"
    )
    assert status["StackId"] == stack_id, (
        f"positive control: detection status reported StackId {status['StackId']!r}, "
        f"expected {stack_id!r}"
    )

    unknown_id = "00000000-0000-0000-0000-000000000000"
    err = _expect_error(
        lambda: cfn.describe_stack_drift_detection_status(StackDriftDetectionId=unknown_id)
    ).response["Error"]
    assert err["Code"] == "ValidationError", (
        f"describing an unknown drift detection id returned {err['Code']!r}, expected 'ValidationError'"
    )
    expected_message = f"Stack drift detection result [{unknown_id}] does not exist"
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )


def _wait_stack_status(cfn, stack_name, terminal_statuses, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    while True:
        status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if status in terminal_statuses:
            return status
        if time.monotonic() >= deadline:
            raise AssertionError(f"stack {stack_name!r} did not reach {terminal_statuses}, last={status}")
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


def _expect_error(fn):
    """Call fn(); return the raised ClientError, or raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
