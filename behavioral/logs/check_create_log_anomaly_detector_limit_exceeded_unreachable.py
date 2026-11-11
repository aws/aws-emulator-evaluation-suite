"""create-log-anomaly-detector-limit-exceeded-unreachable."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "create-log-anomaly-detector-limit-exceeded-unreachable"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateLogAnomalyDetector below quota returns a well-formed ARN; GetLogAnomalyDetector echoes
    the log groups, name, frequency and a pre-analysis status; the per-group listing includes it.
    LimitExceededException (500 detectors per Region) is not exercised: exhausting it is unbounded."""
    logs = ctx.client("logs")

    log_group = ctx.unique_name("sim2real-behav-anomalylg-")
    logs.create_log_group(logGroupName=log_group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))
    log_group_arn = logs.describe_log_groups(logGroupNamePrefix=log_group)["logGroups"][0]["arn"]
    # CreateLogAnomalyDetector's logGroupArnList rejects the ":*" suffix that
    # DescribeLogGroups includes on its "arn" field -- it wants the bare log-group ARN.
    if log_group_arn.endswith(":*"):
        log_group_arn = log_group_arn[: -len(":*")]

    detector_name = ctx.unique_name("sim2real-behav-anomalydet-")
    detector_arn = logs.create_log_anomaly_detector(
        logGroupArnList=[log_group_arn],
        detectorName=detector_name,
        evaluationFrequency="ONE_HOUR",
        tags={"Sim2RealOwner": "behavioral-suite"},
    )["anomalyDetectorArn"]
    ctx.on_cleanup(lambda: logs.delete_log_anomaly_detector(anomalyDetectorArn=detector_arn))
    arn_pattern = (
        rf"arn:aws:logs:{re.escape(ctx.region)}:{re.escape(str(ctx.account))}"
        r":anomaly-detector:[A-Za-z0-9-]+"
    )
    assert re.fullmatch(arn_pattern, detector_arn), (
        f"expected an anomaly detector ARN matching {arn_pattern!r}, got {detector_arn!r}"
    )

    described = logs.get_log_anomaly_detector(anomalyDetectorArn=detector_arn)
    assert described["logGroupArnList"] == [log_group_arn], (
        f"GetLogAnomalyDetector returned logGroupArnList {described.get('logGroupArnList')!r}, "
        f"expected {[log_group_arn]!r}"
    )
    assert described["detectorName"] == detector_name, (
        f"GetLogAnomalyDetector returned detectorName {described.get('detectorName')!r}, "
        f"expected {detector_name!r}"
    )
    assert described["evaluationFrequency"] == "ONE_HOUR", (
        f"evaluationFrequency did not round-trip: {described.get('evaluationFrequency')!r}"
    )
    assert described["anomalyDetectorStatus"] in (
        "INITIALIZING",
        "TRAINING",
        "ANALYZING",
    ), (
        f"expected the freshly created detector to be in a valid pre-exhaustion lifecycle "
        f"state, got {described['anomalyDetectorStatus']!r}"
    )

    # The detector is discoverable through the log group it was created for, not only
    # through the ARN the create call happened to return.
    listed = logs.list_log_anomaly_detectors(filterLogGroupArn=log_group_arn)[
        "anomalyDetectors"
    ]
    assert detector_arn in [d["anomalyDetectorArn"] for d in listed], (
        f"ListLogAnomalyDetectors filtered on {log_group_arn} did not return "
        f"{detector_arn}: {listed!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
