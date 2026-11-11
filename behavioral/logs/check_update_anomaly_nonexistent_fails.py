"""update-anomaly-nonexistent-fails."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "update-anomaly-nonexistent-fails"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateAnomaly for an unknown anomaly id raises ResourceNotFoundException,
    even though the referenced detector itself exists."""
    logs = ctx.client("logs")

    log_group_name = ctx.unique_name("sim2real-behav-lg-")
    logs.create_log_group(logGroupName=log_group_name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_name))
    log_group_arn = logs.describe_log_groups(logGroupNamePrefix=log_group_name)["logGroups"][0]["arn"]
    # describe_log_groups returns the ARN with a trailing ":*" (denoting "all
    # log streams"); CreateLogAnomalyDetector's logGroupArnList validates
    # against the bare log-group ARN pattern and rejects that suffix.
    if log_group_arn.endswith(":*"):
        log_group_arn = log_group_arn[: -len(":*")]

    detector_arn = logs.create_log_anomaly_detector(
        logGroupArnList=[log_group_arn], tags={"Sim2RealOwner": "behavioral-suite"}
    )["anomalyDetectorArn"]
    ctx.on_cleanup(lambda: logs.delete_log_anomaly_detector(anomalyDetectorArn=detector_arn))

    bogus_anomaly_id = str(uuid.uuid4())  # well-formed (36 chars) but never actually reported

    code, message = _client_error(
        lambda: logs.update_anomaly(anomalyDetectorArn=detector_arn, anomalyId=bogus_anomaly_id)
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == f"No matching anomaly found for anomalyId: {bogus_anomaly_id}", (
        f"unexpected UpdateAnomaly not-found message: {message!r}"
    )

    # Independent read at the destination: the rejected UpdateAnomaly must not have fabricated
    # the anomaly it was told to act on.
    anomalies = logs.list_anomalies(anomalyDetectorArn=detector_arn)["anomalies"]
    assert anomalies == [], f"rejected UpdateAnomaly left a trace in ListAnomalies: {anomalies}"


def _client_error(fn):
    try:
        result = fn()
    except Exception as exc:  # botocore.exceptions.ClientError
        response = getattr(exc, "response", None)
        if response is not None:
            err = response.get("Error", {})
            return err.get("Code"), err.get("Message")
        raise
    raise AssertionError(
        f"expected UpdateAnomaly to raise ResourceNotFoundException for an unknown "
        f"anomalyId, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
