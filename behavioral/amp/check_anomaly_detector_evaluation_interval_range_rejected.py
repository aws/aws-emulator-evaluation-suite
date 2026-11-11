"""anomaly-detector-evaluation-interval-range-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "anomaly-detector-evaluation-interval-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["amp"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAnomalyDetector with a Random Cut Forest query not rooted in an aggregation operator is
    refused with ValidationException and the exact message and creates no detector, while the
    same alias with a wrapped query reaches ACTIVE."""
    amp = ctx.client("amp")
    workspace_id = amp.create_workspace(alias=ctx.unique_name("sim2real-amp-ws-"), tags=_mgmt_tags())["workspaceId"]
    ctx.on_cleanup(lambda: amp.delete_workspace(workspaceId=workspace_id))
    _poll_until(
        lambda: amp.describe_workspace(workspaceId=workspace_id)["workspace"]["status"]["statusCode"],
        lambda s: s == "ACTIVE",
        timeout_s=120,
    )

    alias = ctx.unique_name("sim2real-ad-range-")

    # "up" is valid PromQL that passes client-side validation, but AMP requires an RCF query
    # rooted in a supported aggregation operator.
    bad_config = {"randomCutForest": {"query": "up"}}
    code, message = _error(
        lambda: amp.create_anomaly_detector(
            workspaceId=workspace_id,
            alias=alias,
            configuration=bad_config,
            evaluationIntervalInSeconds=60,
            tags=_mgmt_tags(),
        )
    )
    assert code == "ValidationException", f"expected ValidationException for unwrapped RCF query, got {code}"
    expected = "Unsupported PromQL expression for RandomCutForest, expression's root must be a supported aggregation operator"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: no detector under this alias exists.
    listed = amp.list_anomaly_detectors(workspaceId=workspace_id, alias=alias)["anomalyDetectors"]
    assert listed == [], f"a detector was created despite the rejected unwrapped-query request: {listed}"

    # Positive control: the same alias with a properly wrapped query succeeds.
    good_config = {"randomCutForest": {"query": "sum(up)"}}
    created = amp.create_anomaly_detector(
        workspaceId=workspace_id,
        alias=alias,
        configuration=good_config,
        evaluationIntervalInSeconds=60,
        tags=_mgmt_tags(),
    )
    detector_id = created["anomalyDetectorId"]
    ctx.on_cleanup(lambda: amp.delete_anomaly_detector(workspaceId=workspace_id, anomalyDetectorId=detector_id))
    status = _poll_until(
        lambda: amp.describe_anomaly_detector(workspaceId=workspace_id, anomalyDetectorId=detector_id)["anomalyDetector"]["status"]["statusCode"],
        lambda s: s in ("ACTIVE", "CREATION_FAILED"),
        timeout_s=120,
    )
    assert status == "ACTIVE", f"expected the corrected, wrapped-query detector to reach ACTIVE, got {status!r}"


def _mgmt_tags():
    return {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _error(fn):
    """Call fn(), which must fail; return its botocore error (code, message). An unexpected
    SUCCESS raises, so a target that accepts what AWS refuses is never read as a mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
