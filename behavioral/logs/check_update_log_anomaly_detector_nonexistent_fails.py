"""update-log-anomaly-detector-nonexistent-fails."""
from __future__ import annotations

import uuid
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "update-log-anomaly-detector-nonexistent-fails"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateLogAnomalyDetector against an anomaly detector ARN that was never created
    raises ResourceNotFoundException with its exact message."""
    logs = ctx.client("logs")

    group = ctx.unique_name("sim2real-ulaneg-lg-")
    logs.create_log_group(logGroupName=group)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    group_arn = _log_group_arn(logs, group)

    detector_arn = logs.create_log_anomaly_detector(logGroupArnList=[group_arn])[
        "anomalyDetectorArn"
    ]
    ctx.on_cleanup(lambda: logs.delete_log_anomaly_detector(anomalyDetectorArn=detector_arn))

    # Positive control: updating a real, existing detector succeeds and is reflected on read.
    logs.update_log_anomaly_detector(
        anomalyDetectorArn=detector_arn, enabled=False, evaluationFrequency="TEN_MIN"
    )
    got = logs.get_log_anomaly_detector(anomalyDetectorArn=detector_arn)
    assert got["anomalyDetectorStatus"] == "PAUSED", (
        f"expected UpdateLogAnomalyDetector(enabled=False) to pause the detector, got {got!r}"
    )

    # Negative: an anomaly detector ARN that was never created is rejected.
    bogus_arn = f"arn:aws:logs:{ctx.region}:{ctx.account}:anomaly-detector:{uuid.uuid4()}"
    code, message = _error(
        lambda: logs.update_log_anomaly_detector(
            anomalyDetectorArn=bogus_arn, enabled=True, evaluationFrequency="TEN_MIN"
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for an anomaly detector that was never "
        f"created, got {code!r} {message!r}"
    )
    expected_message = f"The specified ARN does not exist or already deleted : {bogus_arn}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect-absent: the real detector's state was not disturbed by the rejected call.
    still_paused = logs.get_log_anomaly_detector(anomalyDetectorArn=detector_arn)
    assert still_paused["anomalyDetectorStatus"] == "PAUSED", (
        f"expected the real detector to stay PAUSED after the rejected call against a "
        f"different (nonexistent) ARN, got {still_paused!r}"
    )


def _log_group_arn(logs, name: str) -> str:
    for g in logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]:
        if g["logGroupName"] == name:
            return g["logGroupArn"]
    raise AssertionError(f"log group {name!r} not found via DescribeLogGroups")


def _error(fn: Callable[[], Any]):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
