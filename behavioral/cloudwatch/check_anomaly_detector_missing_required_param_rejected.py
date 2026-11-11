"""anomaly-detector-missing-required-param-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "anomaly-detector-missing-required-param-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutAnomalyDetector naming no metric (no Namespace/MetricName/Stat, no Single- or
    MetricMathAnomalyDetector) fails with MissingParameter "Input missing required parameter." and
    creates no detector; the call naming a metric creates an untrained one."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2Real/CWAnomalyMissingParam")
    metric_name = ctx.unique_name("sim2real-anomaly-missing-param-metric-")

    # PutAnomalyDetector has no unconditionally required member: the metric can be identified via
    # the deprecated trio OR either *AnomalyDetector object. When none of them is supplied,
    # CloudWatch reports MissingParameter (InvalidParameterCombination is for conflicting members).
    code, message = _error(lambda: cw.put_anomaly_detector())
    assert code == "MissingParameter", f"expected MissingParameter, got {code}"
    assert message == "Input missing required parameter.", (
        f"expected the exact refusal message 'Input missing required parameter.', got {message!r}"
    )

    # effect-absent: the rejected call must not have created a detector anyone could see,
    # checked against a namespace/metric this check never sent on the rejected call
    detectors = cw.describe_anomaly_detectors(Namespace=namespace, MetricName=metric_name)["AnomalyDetectors"]
    assert detectors == [], f"rejected PutAnomalyDetector call unexpectedly created: {detectors}"

    # positive control: the identical intent, with the metric actually identified, succeeds --
    # this is what tells "rejects a call naming no metric" apart from "rejects every call"
    cw.put_anomaly_detector(Namespace=namespace, MetricName=metric_name, Stat="Average")
    ctx.on_cleanup(lambda: cw.delete_anomaly_detector(Namespace=namespace, MetricName=metric_name, Stat="Average"))
    detectors_after = cw.describe_anomaly_detectors(Namespace=namespace, MetricName=metric_name)["AnomalyDetectors"]
    assert len(detectors_after) == 1, f"expected exactly 1 anomaly detector, got {detectors_after}"
    assert detectors_after[0]["StateValue"] in ("PENDING_TRAINING", "TRAINED_INSUFFICIENT_DATA"), detectors_after[0]["StateValue"]


def _error(fn):
    """Return (code, message) of the ClientError fn raises. A SUCCESS is an AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
