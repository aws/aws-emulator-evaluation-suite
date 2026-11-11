"""op-contract-describeAnomalyDetectors."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-describeAnomalyDetectors"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAnomalyDetectors filters by Namespace/MetricName and reports each detector's
    StateValue; combining AnomalyDetectorIds with the deprecated Namespace/MetricName filters
    in the same call is rejected with InvalidParameterCombination."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-cw-ns-")
    metric_name = "QueueDepth"

    cw.put_anomaly_detector(Namespace=namespace, MetricName=metric_name, Stat="Average")
    ctx.on_cleanup(
        lambda: cw.delete_anomaly_detector(Namespace=namespace, MetricName=metric_name, Stat="Average")
    )

    detectors = _poll_until(
        lambda: cw.describe_anomaly_detectors(Namespace=namespace, MetricName=metric_name)[
            "AnomalyDetectors"
        ],
        lambda ds: len(ds) == 1,
        timeout_s=30,
        timeout_msg=lambda ds: (
            f"expected exactly 1 anomaly detector for {namespace}/{metric_name} within 30s, "
            f"last describe returned {len(ds)}"
        ),
    )
    assert len(detectors) == 1, f"expected exactly 1 detector, got {len(detectors)}: {detectors}"
    assert detectors[0]["Namespace"] == namespace, (
        f"expected Namespace {namespace!r}, got {detectors[0]['Namespace']!r}"
    )
    assert detectors[0]["MetricName"] == metric_name, (
        f"expected MetricName {metric_name!r}, got {detectors[0]['MetricName']!r}"
    )
    assert detectors[0]["StateValue"] in ("PENDING_TRAINING", "TRAINED_INSUFFICIENT_DATA", "TRAINED"), (
        f"unexpected StateValue {detectors[0]['StateValue']!r}"
    )

    code, message = _client_error(
        lambda: cw.describe_anomaly_detectors(
            AnomalyDetectorIds=["00000000-0000-0000-0000-000000000000"], Namespace=namespace
        )
    )
    assert code == "InvalidParameterCombination", (
        f"expected InvalidParameterCombination mixing AnomalyDetectorIds with Namespace, got {code}"
    )
    expected_message = (
        'AnomalyDetectorIds cannot be combined with metric filters (Namespace, '
        'MetricName, Dimensions, AnomalyDetectorTypes, or '
        'AnomalyDetectorSearchTerms). Provide either AnomalyDetectorIds for a '
        'direct lookup, or metric filters to list, but not both.'
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _client_error(fn):
    """Call fn; return the (code, message) of the ClientError it raises.

    Raises AssertionError when the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=30.0, interval_s=1.0, timeout_msg=None):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result) and time.monotonic() < deadline:
        time.sleep(interval_s)
        result = probe()
    if not predicate(result):
        msg = timeout_msg(result) if timeout_msg else f"timed out after {timeout_s}s, last result: {result!r}"
        raise AssertionError(msg)
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
