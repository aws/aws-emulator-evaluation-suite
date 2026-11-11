"""put-anomaly-detector-invalid-stat-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-anomaly-detector-invalid-stat-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutAnomalyDetector with an unsupported statistic string is rejected instead of
    silently being accepted as an opaque label, and the identical call with a real
    statistic succeeds against the same namespace/metric."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2Real/CWAnomalyStat")
    metric_name = ctx.unique_name("sim2real-anomaly-stat-metric-")

    code, message = _client_error(
        lambda: cw.put_anomaly_detector(
            Namespace=namespace,
            MetricName=metric_name,
            Stat="NotARealStatistic",
        )
    )
    # Real CloudWatch rejects an unsupported `Stat` value with a top-level request
    # validation error (observed on real AWS as `ValidationError`) rather than the
    # operation-specific InvalidParameterValueException the API reference
    # enumerates.
    assert code == "ValidationError", f"expected a Stat-validation rejection, got {code}"
    expected_message = (
        "1 validation error detected: Value 'NotARealStatistic' at 'stat' "
        'failed to satisfy constraint: Member must satisfy regular expression '
        'pattern: '
        '(SampleCount|Average|Sum|Minimum|Maximum|IQM|(p|tc|tm|ts|wm)(\\d{1,2}(\\.\\d{0,10})?|100)|[ou]\\d+(\\.\\d*)?)(_E|_L|_H)?|(TM|TC|TS|WM)\\(((((\\d{1,2})(\\.\\d{0,10})?|100(\\.0{0,10})?)%)?:((\\d{1,2})(\\.\\d{0,10})?|100(\\.0{0,10})?)%|((\\d{1,2})(\\.\\d{0,10})?|100(\\.0{0,10})?)%:(((\\d{1,2})(\\.\\d{0,10})?|100(\\.0{0,10})?)%)?)\\)|(TM|TC|TS|WM|PR)\\(((\\d+(\\.\\d{0,10})?|(\\d+(\\.\\d{0,10})?[Ee][+-]?\\d+)):((\\d+(\\.\\d{0,10})?|(\\d+(\\.\\d{0,10})?[Ee][+-]?\\d+)))?|((\\d+(\\.\\d{0,10})?|(\\d+(\\.\\d{0,10})?[Ee][+-]?\\d+)))?:(\\d+(\\.\\d{0,10})?|(\\d+(\\.\\d{0,10})?[Ee][+-]?\\d+)))\\)'
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # the rejected call must not have created a detector under this namespace/metric
    detectors = cw.describe_anomaly_detectors(Namespace=namespace, MetricName=metric_name)[
        "AnomalyDetectors"
    ]
    assert detectors == [], f"rejected PutAnomalyDetector unexpectedly created: {detectors}"

    # positive control: the identical intent with a real Stat succeeds -- proves the
    # rejection above targets the malformed Stat, not every PutAnomalyDetector call
    cw.put_anomaly_detector(Namespace=namespace, MetricName=metric_name, Stat="Average")
    ctx.on_cleanup(
        lambda: cw.delete_anomaly_detector(Namespace=namespace, MetricName=metric_name, Stat="Average")
    )
    detectors_after = cw.describe_anomaly_detectors(Namespace=namespace, MetricName=metric_name)[
        "AnomalyDetectors"
    ]
    assert len(detectors_after) == 1, f"expected 1 detector after positive control, got {detectors_after}"


def _client_error(fn):
    """Call fn; return the (code, message) of the ClientError it raises.

    Raises AssertionError when the call succeeds."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
