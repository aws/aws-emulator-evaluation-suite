"""update-log-anomaly-detector-and-list-anomalies."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-log-anomaly-detector-and-list-anomalies"
GROUP = 'anomaly-detector'
SERVICES = ['logs']

def _create_log_group(ctx, logs, name=None, **kwargs) -> str:
    name = name or ctx.unique_name("sim2real-behav-lg-")
    logs.create_log_group(
        logGroupName=name, tags={"Sim2RealOwner": "behavioral-suite"}, **kwargs
    )
    ctx.on_cleanup(lambda: _delete_log_group(logs, name))
    return name


def _poll_until(probe, predicate, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _delete_log_group(logs, name) -> None:
    """Drop deletion protection (if any) before deleting, mirroring the suite's teardown."""
    try:
        logs.put_log_group_deletion_protection(
            logGroupIdentifier=name, deletionProtectionEnabled=False
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    logs.delete_log_group(logGroupName=name)

@tags("axis:happy-path", "cap:c1", "concern:metrics", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateLogAnomalyDetector mutates the detector in place and ListAnomalies is queryable."""
    logs = ctx.client("logs")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    group = _create_log_group(ctx, logs)
    group_arn = f"arn:aws:logs:{ctx.region}:{account_id}:log-group:{group}"
    detector_arn = logs.create_log_anomaly_detector(
        logGroupArnList=[group_arn],
        detectorName=ctx.unique_name("sim2real-behav-ad-upd-"),
        evaluationFrequency="FIFTEEN_MIN",
        tags={"sim2real": CHECK},
    )["anomalyDetectorArn"]
    ctx.on_cleanup(
        lambda: logs.delete_log_anomaly_detector(anomalyDetectorArn=detector_arn)
    )

    try:
        logs.update_log_anomaly_detector(
            anomalyDetectorArn=detector_arn,
            evaluationFrequency="ONE_HOUR",
            enabled=False,
        )
        # PAUSED is the specific terminal status a disabled detector reaches; a broad
        # accept-set here would pass a target that ignored `enabled` entirely.
        got = _poll_until(
            lambda: logs.get_log_anomaly_detector(anomalyDetectorArn=detector_arn),
            lambda g: g["anomalyDetectorStatus"] == "PAUSED",
            timeout_s=60,
            interval_s=3,
        )
        assert got["evaluationFrequency"] == "ONE_HOUR", f"update not reflected: {got}"

        anomalies = logs.list_anomalies(anomalyDetectorArn=detector_arn).get("anomalies", [])
        assert anomalies == [], f"expected no anomalies on a brand new detector: {anomalies}"
    finally:
        logs.delete_log_anomaly_detector(anomalyDetectorArn=detector_arn)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
