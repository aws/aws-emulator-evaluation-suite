"""anomaly-detector-create-delete-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "anomaly-detector-create-delete-lifecycle"
GROUP = "state"
SERVICES = ["amp"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAnomalyDetector transitions CREATING -> ACTIVE with the submitted configuration
    intact, and DeleteAnomalyDetector removes it (ACTIVE -> DELETING -> gone), and the dead
    detector is genuinely unusable afterward, not merely absent from Describe."""
    amp = ctx.client("amp")
    workspace_id = amp.create_workspace(
        alias=ctx.unique_name("sim2real-amp-ws-"), tags={"sim2real-owner": "behavioral"}
    )["workspaceId"]
    ctx.on_cleanup(lambda: amp.delete_workspace(workspaceId=workspace_id))
    _poll_until(
        lambda: amp.describe_workspace(workspaceId=workspace_id)["workspace"]["status"]["statusCode"],
        lambda s: s == "ACTIVE",
        timeout_s=120,
    )

    alias = ctx.unique_name("sim2real-ad-")
    config = {"randomCutForest": {"query": "sum(up)", "shingleSize": 8, "sampleSize": 256}}
    created = amp.create_anomaly_detector(
        workspaceId=workspace_id,
        alias=alias,
        configuration=config,
        evaluationIntervalInSeconds=60,
        tags={"sim2real-owner": "behavioral"},
    )
    detector_id = created["anomalyDetectorId"]
    detector_arn = created["arn"]
    assert detector_id.startswith("ad-"), f"expected an ad- id, got {detector_id!r}"

    status = _poll_until(
        lambda: amp.describe_anomaly_detector(workspaceId=workspace_id, anomalyDetectorId=detector_id)["anomalyDetector"]["status"]["statusCode"],
        lambda s: s in ("ACTIVE", "CREATION_FAILED"),
        timeout_s=120,
    )
    assert status == "ACTIVE", f"expected ACTIVE, got {status}"

    described = amp.describe_anomaly_detector(workspaceId=workspace_id, anomalyDetectorId=detector_id)["anomalyDetector"]
    assert described["alias"] == alias, f"expected alias {alias!r}, got {described['alias']!r}"
    assert described["configuration"]["randomCutForest"]["query"] == "sum(up)", (
        f"expected submitted query 'sum(up)' to round-trip, got {described['configuration']['randomCutForest']['query']!r}"
    )

    amp.delete_anomaly_detector(workspaceId=workspace_id, anomalyDetectorId=detector_id)

    def _describe_state():
        try:
            amp.describe_anomaly_detector(workspaceId=workspace_id, anomalyDetectorId=detector_id)
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        return "present", None

    gone = _poll_until(_describe_state, lambda r: r[0] != "present", timeout_s=120)
    assert gone == ("ResourceNotFoundException", "Anomaly detector not found."), gone

    # Gone means unusable, not just absent from Describe: a mutation against the same ARN
    # (TagResource, a call that never recreates the resource) is rejected too.
    tagged = _error(lambda: amp.tag_resource(resourceArn=detector_arn, tags={"sim2real-owner": "behavioral"}))
    assert tagged == ("NotFoundException", "Resource was not found"), tagged


def _error(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("expected a rejection, call unexpectedly succeeded")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s, last value={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
