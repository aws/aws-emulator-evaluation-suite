"""list-log-anomaly-detectors-reflects-lifecycle-changes."""
from __future__ import annotations

import time
from typing import Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-log-anomaly-detectors-reflects-lifecycle-changes"
GROUP = "data-plane"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListLogAnomalyDetectors reflects detector creation immediately, and GetLogAnomalyDetector
    agrees with that listing while the detector is live; after deletion the detector disappears
    from ListLogAnomalyDetectors (bounded poll)."""
    logs = ctx.client("logs")

    group = ctx.unique_name("sim2real-anomaly-lg-")
    logs.create_log_group(logGroupName=group)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    group_arn = logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"][0]["arn"]
    # CreateLogAnomalyDetector/ListLogAnomalyDetectors reject the trailing ":*" that
    # DescribeLogGroups appends to log group ARNs (pattern [\w#+=/:,.@-]* excludes "*").
    plain_arn = group_arn.removesuffix(":*")

    detector_name = ctx.unique_name("sim2real-detector-")

    def _listed_arns() -> list[str]:
        arns: list[str] = []
        token = None
        while True:
            kwargs = {"filterLogGroupArn": plain_arn}
            if token:
                kwargs["nextToken"] = token
            resp = logs.list_log_anomaly_detectors(**kwargs)
            arns.extend(d["anomalyDetectorArn"] for d in resp.get("anomalyDetectors", []))
            token = resp.get("nextToken")
            if not token:
                break
        return arns

    detector_arn = logs.create_log_anomaly_detector(
        logGroupArnList=[plain_arn],
        detectorName=detector_name,
        evaluationFrequency="TEN_MIN",
    )["anomalyDetectorArn"]
    ctx.on_cleanup(lambda: _safe_delete_detector(logs, detector_arn))

    appeared = _poll_until(lambda: detector_arn in _listed_arns(), timeout_s=30.0, interval_s=2.0)
    assert appeared, "newly created anomaly detector did not appear in ListLogAnomalyDetectors"

    get_resp = logs.get_log_anomaly_detector(anomalyDetectorArn=detector_arn)
    assert get_resp["detectorName"] == detector_name
    assert plain_arn in get_resp["logGroupArnList"]
    assert get_resp["anomalyDetectorStatus"] in ("INITIALIZING", "TRAINING", "ANALYZING")

    logs.delete_log_anomaly_detector(anomalyDetectorArn=detector_arn)

    disappeared = _poll_until(lambda: detector_arn not in _listed_arns(), timeout_s=60.0, interval_s=3.0)
    assert disappeared, "deleted anomaly detector still appeared in ListLogAnomalyDetectors"


def _safe_delete_detector(logs, arn: str) -> None:
    try:
        logs.delete_log_anomaly_detector(anomalyDetectorArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(predicate: Callable[[], bool], timeout_s: float, interval_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval_s)
    return predicate()


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
