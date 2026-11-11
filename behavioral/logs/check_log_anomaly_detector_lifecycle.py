"""log-anomaly-detector-lifecycle."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "log-anomaly-detector-lifecycle"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateLogAnomalyDetector -> Get/List -> Update(pause/resume) -> Delete transitions
    the detector through a consistent status lifecycle and each read reflects it."""
    logs = ctx.client("logs")

    log_group_name = ctx.unique_name("sim2real-logs-anomdet-lg-")
    logs.create_log_group(logGroupName=log_group_name)
    ctx.on_cleanup(lambda: _safe_delete_log_group(logs, log_group_name))
    log_group_arn = _get_log_group_arn(logs, log_group_name)

    detector_name = ctx.unique_name("sim2real-anomdet-")
    create_resp = logs.create_log_anomaly_detector(
        logGroupArnList=[log_group_arn],
        detectorName=detector_name,
        evaluationFrequency="TEN_MIN",
    )
    detector_arn = create_resp["anomalyDetectorArn"]
    ctx.on_cleanup(lambda: _safe_delete_detector(logs, detector_arn))

    # GetLogAnomalyDetector reflects the creation parameters and a live (non-terminal) status.
    got = logs.get_log_anomaly_detector(anomalyDetectorArn=detector_arn)
    assert got["logGroupArnList"] == [log_group_arn]
    assert got["evaluationFrequency"] == "TEN_MIN"
    assert got["anomalyDetectorStatus"] in ("INITIALIZING", "TRAINING", "ANALYZING"), got[
        "anomalyDetectorStatus"
    ]

    # ListLogAnomalyDetectors (filtered by the log group) surfaces the new detector.
    def _listed() -> bool:
        resp = logs.list_log_anomaly_detectors(filterLogGroupArn=log_group_arn)
        return any(d["anomalyDetectorArn"] == detector_arn for d in resp.get("anomalyDetectors", []))

    assert _poll_until(_listed, timeout_s=30, interval_s=3), (
        "detector did not appear in ListLogAnomalyDetectors(filterLogGroupArn=...)"
    )

    # UpdateLogAnomalyDetector(enabled=False) pauses the detector.
    logs.update_log_anomaly_detector(anomalyDetectorArn=detector_arn, enabled=False)

    def _paused() -> bool:
        return logs.get_log_anomaly_detector(anomalyDetectorArn=detector_arn)["anomalyDetectorStatus"] == "PAUSED"

    assert _poll_until(_paused, timeout_s=60, interval_s=3), "detector did not transition to PAUSED"

    # UpdateLogAnomalyDetector(enabled=True) resumes it out of PAUSED.
    logs.update_log_anomaly_detector(anomalyDetectorArn=detector_arn, enabled=True)

    def _resumed() -> bool:
        status = logs.get_log_anomaly_detector(anomalyDetectorArn=detector_arn)["anomalyDetectorStatus"]
        return status in ("INITIALIZING", "TRAINING", "ANALYZING")

    assert _poll_until(_resumed, timeout_s=60, interval_s=3), "detector did not resume out of PAUSED"

    # DeleteLogAnomalyDetector removes it; subsequent reads fail with ResourceNotFoundException.
    logs.delete_log_anomaly_detector(anomalyDetectorArn=detector_arn)

    def _deleted() -> bool:
        try:
            logs.get_log_anomaly_detector(anomalyDetectorArn=detector_arn)
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException"
        return False

    assert _poll_until(_deleted, timeout_s=30, interval_s=3), "detector still retrievable after delete"

    # A mutation on the now-dead id fails the same way a read does: the id is
    # unusable, not merely unreadable.
    update_code, update_code_msg = _error_code(
        lambda: logs.update_log_anomaly_detector(anomalyDetectorArn=detector_arn, enabled=True)
    )
    assert update_code == "ResourceNotFoundException", (
        f"UpdateLogAnomalyDetector on a deleted detector should fail with "
        f"ResourceNotFoundException, got {update_code}"
    )
    expected = f"The specified ARN does not exist or already deleted : {detector_arn}"
    assert update_code_msg == expected, f"expected message {expected!r}, got {update_code_msg!r}"


def _poll_until(probe: Callable[[], bool], *, timeout_s: float, interval_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while True:
        if probe():
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(interval_s)


def _error_code(fn):
    """The AWS (code, message) fn() raised. An unexpected SUCCESS raises, so a target that
    accepts what AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"the call was expected to be refused but it succeeded, returning {result!r}")


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


def _safe_delete_detector(logs: Any, detector_arn: str) -> None:
    try:
        logs.delete_log_anomaly_detector(anomalyDetectorArn=detector_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
