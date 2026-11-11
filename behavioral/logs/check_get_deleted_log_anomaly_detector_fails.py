"""get-deleted-log-anomaly-detector-fails."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-deleted-log-anomaly-detector-fails"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetLogAnomalyDetector on a detector ARN that was already deleted returns
    ResourceNotFoundException, not a stale/empty success response."""
    logs = ctx.client("logs")

    log_group_name = ctx.unique_name("sim2real-logs-anomdet-lg-")
    logs.create_log_group(logGroupName=log_group_name)
    ctx.on_cleanup(lambda: _safe_delete_log_group(logs, log_group_name))
    log_group_arn = _get_log_group_arn(logs, log_group_name)

    detector_name = ctx.unique_name("sim2real-anomdet-")
    create_resp = logs.create_log_anomaly_detector(
        logGroupArnList=[log_group_arn],
        detectorName=detector_name,
    )
    detector_arn = create_resp["anomalyDetectorArn"]

    # Positive control: the detector is retrievable and reflects what was actually
    # created before deletion. Without this, the "not found after delete" beat below
    # cannot distinguish a real transition from a Get that never worked at all.
    before = logs.get_log_anomaly_detector(anomalyDetectorArn=detector_arn)
    assert before.get("detectorName") == detector_name, (
        f"expected GetLogAnomalyDetector to reflect detectorName={detector_name!r} "
        f"before deletion, got {before.get('detectorName')!r}"
    )

    logs.delete_log_anomaly_detector(anomalyDetectorArn=detector_arn)

    def _gone() -> bool:
        try:
            logs.get_log_anomaly_detector(anomalyDetectorArn=detector_arn)
        except ClientError:
            return True
        return False

    assert _poll_until(_gone, timeout_s=30, interval_s=3), (
        "GetLogAnomalyDetector still served a deleted detector after 30s"
    )
    code, message = _error(lambda: logs.get_log_anomaly_detector(anomalyDetectorArn=detector_arn))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from GetLogAnomalyDetector on a deleted detector, got {code!r}"
    )
    expected_message = f"The specified ARN does not exist or already deleted : {detector_arn}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The id is truly gone, not merely lagging behind in Get: a mutation against the
    # same deleted ARN must also fail with the specific not-found error.
    delete_again_code, delete_again_message = _error(
        lambda: logs.delete_log_anomaly_detector(anomalyDetectorArn=detector_arn)
    )
    assert delete_again_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException deleting an already-deleted detector, "
        f"got {delete_again_code!r}"
    )
    expected_message = f"The specified ARN does not exist or already deleted : {detector_arn}"
    assert delete_again_message == expected_message, (
        f"expected message {expected_message!r}, got {delete_again_message!r}"
    )


def _poll_until(probe: Callable[[], bool], *, timeout_s: float, interval_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while True:
        if probe():
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(interval_s)


def _error(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """Call fn(); return its ClientError code and message. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _get_log_group_arn(logs: Any, log_group_name: str) -> str:
    resp = logs.describe_log_groups(logGroupNamePrefix=log_group_name)
    for group in resp.get("logGroups", []):
        if group["logGroupName"] == log_group_name:
            arn = group["arn"]
            # DescribeLogGroups returns the canonical log-group ARN with a trailing
            # ":*" wildcard suffix. CreateLogAnomalyDetector's logGroupArnList
            # entries are validated against a pattern that does not allow "*", so
            # that suffix must be stripped before it is used here.
            if arn.endswith(":*"):
                arn = arn[: -len(":*")]
            return arn
    raise AssertionError(f"log group {log_group_name} not found via DescribeLogGroups")


def _safe_delete_log_group(logs: Any, log_group_name: str) -> None:
    try:
        logs.delete_log_group(logGroupName=log_group_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
