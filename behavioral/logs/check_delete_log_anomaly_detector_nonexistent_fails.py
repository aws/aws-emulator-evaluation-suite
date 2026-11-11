"""delete-log-anomaly-detector-nonexistent-fails."""
from __future__ import annotations

import uuid
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "delete-log-anomaly-detector-nonexistent-fails"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A real anomaly detector deletes; afterwards GetLogAnomalyDetector and a second delete on its ARN, and a
    delete on a never-existing ARN, raise ResourceNotFoundException with the exact message naming the ARN.
    """
    logs = ctx.client("logs")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]
    region = ctx.region

    log_group_name = ctx.unique_name("sim2real-behav-lg-")
    logs.create_log_group(logGroupName=log_group_name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_name))
    log_group_arn = logs.describe_log_groups(logGroupNamePrefix=log_group_name)["logGroups"][0]["arn"]
    if log_group_arn.endswith(":*"):
        log_group_arn = log_group_arn[: -len(":*")]

    detector_arn = logs.create_log_anomaly_detector(logGroupArnList=[log_group_arn])[
        "anomalyDetectorArn"
    ]

    # Positive control: deleting a real detector must succeed.
    logs.delete_log_anomaly_detector(anomalyDetectorArn=detector_arn)

    # Independent read (different operation than the mutation): the detector is
    # genuinely gone, not just reported gone by the delete call itself.
    gone_code, gone_msg = _error(lambda: logs.get_log_anomaly_detector(anomalyDetectorArn=detector_arn))
    assert gone_code == "ResourceNotFoundException", (
        f"expected a deleted anomaly detector to be independently unreadable via "
        f"GetLogAnomalyDetector with ResourceNotFoundException, got {gone_code}"
    )
    assert gone_msg == _not_found(detector_arn), f"unexpected not-found message {gone_msg!r}"

    # A deleted detector's ARN cannot be deleted again.
    code, message = _error(lambda: logs.delete_log_anomaly_detector(anomalyDetectorArn=detector_arn))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for DeleteLogAnomalyDetector on an "
        f"already-deleted ARN, got {code}"
    )
    assert message == _not_found(detector_arn), f"unexpected not-found message {message!r}"

    # A never-existed ARN gets the same treatment.
    fake_arn = f"arn:aws:logs:{region}:{account}:anomaly-detector:{uuid.uuid4()}"
    code, message = _error(lambda: logs.delete_log_anomaly_detector(anomalyDetectorArn=fake_arn))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for DeleteLogAnomalyDetector on an "
        f"unknown ARN, got {code}"
    )
    assert message == _not_found(fake_arn), f"unexpected not-found message {message!r}"


def _not_found(arn: str) -> str:
    return f"The specified ARN does not exist or already deleted : {arn}"


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """The (code, message) fn() raised. A success raises: a target that accepts a call real AWS
    refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
