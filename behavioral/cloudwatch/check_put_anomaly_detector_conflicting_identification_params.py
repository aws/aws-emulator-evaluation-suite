"""put-anomaly-detector-conflicting-identification-params."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-anomaly-detector-conflicting-identification-params"
GROUP = 'overly-permissive'
SERVICES = ['cloudwatch']

def _client_error(fn):
    """Call fn; return the (code, message) of the ClientError it raises.

    Raises AssertionError when the call succeeds."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutAnomalyDetector rejects mixing classic metric params with SingleMetricAnomalyDetector (overly-permissive check)."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-behav-cwprobe-ns-")
    metric_name = "Latency"

    def _find():
        return cw.describe_anomaly_detectors(
            Namespace=namespace, MetricName=metric_name
        ).get("AnomalyDetectors", [])

    # positive control: a valid single-metric detector against this exact namespace/metric
    # proves the account and credentials are otherwise healthy for PutAnomalyDetector.
    cw.put_anomaly_detector(Namespace=namespace, MetricName=metric_name, Stat="Average")
    ctx.on_cleanup(
        lambda: cw.delete_anomaly_detector(Namespace=namespace, MetricName=metric_name, Stat="Average")
    )
    before = _find()
    assert len(before) == 1, f"expected the control detector to exist, got {before}"

    def op():
        return cw.put_anomaly_detector(
            Namespace=namespace,
            MetricName=metric_name,
            Stat="Average",
            SingleMetricAnomalyDetector={
                "Namespace": namespace,
                "MetricName": metric_name,
                "Stat": "Average",
            },
        )

    code, message = _client_error(op)
    assert code == "InvalidParameterCombination", (
        f"expected InvalidParameterCombination for mixed identification params, got {code}"
    )
    expected_message = (
        'Either single metric attributes, SingleMetricAnomalyDetector or '
        'MetricMathAnomalyDetector can be set, found single metric attributes, '
        'SingleMetricAnomalyDetector.'
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect-absent: the rejected call must not have created or replaced a detector
    after = _find()
    assert len(after) == 1, f"conflicting-params call must not change detector count, got {after}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
