"""put-anomaly-detector-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "put-anomaly-detector-lifecycle"
GROUP = 'anomaly-detector'
SERVICES = ['cloudwatch']

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutAnomalyDetector creates a detector that appears via DescribeAnomalyDetectors until deleted."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-behav-cwprobe-ns-")
    metric_name = "Latency"
    spec = {
        "Namespace": namespace,
        "MetricName": metric_name,
        "Stat": "Average",
    }
    ctx.on_cleanup(lambda _n=spec: _delete_detector_if_present(cw, **_n))

    cw.put_anomaly_detector(**spec)

    def probe():
        return cw.describe_anomaly_detectors(Namespace=namespace, MetricName=metric_name)

    resp = _poll_until(probe, lambda r: len(r.get("AnomalyDetectors", [])) > 0, timeout_s=20, interval_s=2)
    detector = resp["AnomalyDetectors"][0]
    assert detector["Namespace"] == namespace, (
        f"expected Namespace {namespace!r}, got {detector['Namespace']!r}"
    )
    assert detector["MetricName"] == metric_name, (
        f"expected MetricName {metric_name!r}, got {detector['MetricName']!r}"
    )
    assert detector["StateValue"] in ("PENDING_TRAINING", "TRAINED_INSUFFICIENT_DATA"), (
        f"a freshly created anomaly detector with no training data must be untrained "
        f"(PENDING_TRAINING or TRAINED_INSUFFICIENT_DATA), got {detector['StateValue']!r}"
    )

    cw.delete_anomaly_detector(**spec)

    resp2 = _poll_until(
        probe, lambda r: len(r.get("AnomalyDetectors", [])) == 0, timeout_s=20, interval_s=2
    )
    assert resp2["AnomalyDetectors"] == [], "anomaly detector must be gone after delete"


def _delete_detector_if_present(cw, **spec) -> None:
    """Teardown: delete the detector unless the body already deleted it; any other error raises."""
    try:
        cw.delete_anomaly_detector(**spec)
    except cw.exceptions.ResourceNotFoundException:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
