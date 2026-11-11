"""get-log-anomaly-detector-nonexistent-fails."""
from __future__ import annotations

import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-log-anomaly-detector-nonexistent-fails"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetLogAnomalyDetector returns a real detector's log group list, and for an unknown detector ARN raises
    ResourceNotFoundException with its exact message."""
    logs = ctx.client("logs")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    region = ctx.region

    log_group_name = ctx.unique_name("sim2real-logs-anomdet-lg-")
    logs.create_log_group(logGroupName=log_group_name)
    ctx.on_cleanup(lambda: _safe_delete_log_group(logs, log_group_name))
    log_group_arn = _get_log_group_arn(logs, log_group_name)

    detector_arn = logs.create_log_anomaly_detector(logGroupArnList=[log_group_arn])[
        "anomalyDetectorArn"
    ]
    ctx.on_cleanup(lambda: _safe_delete_detector(logs, detector_arn))

    # Positive control: GetLogAnomalyDetector succeeds for a real detector, so
    # the account and credentials are otherwise healthy for this call. (The
    # response has no ARN field to echo back; it reflects the log group instead.)
    got = logs.get_log_anomaly_detector(anomalyDetectorArn=detector_arn)
    assert got["logGroupArnList"] == [log_group_arn], got

    bogus_arn = f"arn:aws:logs:{region}:{account_id}:anomaly-detector:{uuid.uuid4()}"

    code, message = _error(lambda: logs.get_log_anomaly_detector(anomalyDetectorArn=bogus_arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected_message = f"The specified ARN does not exist or already deleted : {bogus_arn}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its ClientError code and message. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _get_log_group_arn(logs, log_group_name):
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


def _safe_delete_log_group(logs, log_group_name):
    try:
        logs.delete_log_group(logGroupName=log_group_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_detector(logs, detector_arn):
    try:
        logs.delete_log_anomaly_detector(anomalyDetectorArn=detector_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
