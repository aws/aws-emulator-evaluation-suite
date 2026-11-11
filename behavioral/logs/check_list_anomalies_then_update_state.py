"""list-anomalies-then-update-state."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-anomalies-then-update-state"
GROUP = "state-machine"
SERVICES = ["logs"]


def _error_code(fn):
    """The AWS (code, message) fn() raised. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"the call was expected to be refused but it succeeded, returning {result!r}")


@tags("axis:rejection", "cap:c1", "concern:metrics", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A fresh anomaly detector lists no anomalies, and UpdateAnomaly on a nonexistent anomalyId
    fails with ResourceNotFoundException without creating any anomaly.
    """
    logs = ctx.client("logs")
    log_group_name = ctx.unique_name("sim2real-logs-anomaly-")
    logs.create_log_group(logGroupName=log_group_name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_name))
    log_group_arn = logs.describe_log_groups(logGroupNamePrefix=log_group_name)["logGroups"][0][
        "logGroupArn"
    ]

    detector_arn = logs.create_log_anomaly_detector(
        logGroupArnList=[log_group_arn], tags={"Sim2RealOwner": "behavioral-suite"}
    )["anomalyDetectorArn"]
    ctx.on_cleanup(lambda: logs.delete_log_anomaly_detector(anomalyDetectorArn=detector_arn))

    # Real anomalies need about an hour of training plus anomalous traffic; a new detector has none.
    anomalies = logs.list_anomalies(anomalyDetectorArn=detector_arn)["anomalies"]
    assert anomalies == [], f"expected no anomalies for a freshly created detector, got {anomalies}"

    fake_anomaly_id = str(uuid.uuid4())
    code, code_msg = _error_code(
        lambda: logs.update_anomaly(
            anomalyDetectorArn=detector_arn,
            anomalyId=fake_anomaly_id,
            suppressionType="INFINITE",
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException suppressing a non-existent anomalyId, got {code}"
    )
    expected = f"No matching anomaly found for anomalyId: {fake_anomaly_id}"
    assert code_msg == expected, f"expected message {expected!r}, got {code_msg!r}"
    post_update_anomalies = logs.list_anomalies(anomalyDetectorArn=detector_arn)["anomalies"]
    assert post_update_anomalies == [], (
        f"the rejected UpdateAnomaly call must not fabricate state: expected no anomalies, "
        f"got {post_update_anomalies}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
