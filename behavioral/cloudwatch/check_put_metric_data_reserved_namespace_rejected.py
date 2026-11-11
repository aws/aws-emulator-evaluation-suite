"""put-metric-data-reserved-namespace-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-metric-data-reserved-namespace-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]

_BOGUS_METRIC = "sim2real-behavioral-bogus"


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutMetricData must reject a customer-supplied Namespace beginning with
    'AWS/' -- that prefix is reserved for AWS service-published metrics and an
    emulator that silently accepts it is overly permissive."""
    cw = ctx.client("cloudwatch")

    # Positive control: an ordinary namespace publishes cleanly, so a rejection below is
    # about the reserved prefix specifically, not a broken client or a target that
    # rejects every PutMetricData call.
    namespace = ctx.unique_name("Sim2RealBehav/")
    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[{"MetricName": "PositiveControlMetric", "Value": 1.0}],
    )

    _rejects(
        lambda: cw.put_metric_data(
            Namespace="AWS/EC2",
            MetricData=[{"MetricName": _BOGUS_METRIC, "Value": 1.0}],
        ),
        expected_codes=("InvalidParameterValue", "InvalidParameterValueException"),
    )

    # Independent read at the destination: the rejected datapoint must never surface,
    # so a target that returns the right error code while still ingesting the metric
    # does not pass either.
    surfaced = cw.list_metrics(Namespace="AWS/EC2", MetricName=_BOGUS_METRIC).get("Metrics", [])
    assert surfaced == [], (
        f"rejected metric must never be recorded under the reserved namespace, found {surfaced!r}"
    )


def _rejects(fn, *, expected_codes):
    """Call fn(); assert it raises one of expected_codes. An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        assert code in expected_codes, f"expected one of {expected_codes}, got {code}"
        return
    raise AssertionError(
        f"real AWS rejects PutMetricData into a reserved 'AWS/' namespace, but it "
        f"SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
