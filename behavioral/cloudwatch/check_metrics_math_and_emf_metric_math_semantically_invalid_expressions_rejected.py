"""metrics-math-and-emf-metric-math-semantically-invalid-expressions-rejected."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "metrics-math-and-emf-metric-math-semantically-invalid-expressions-rejected"
GROUP = "metric-math"
SERVICES = ["cloudwatch"]

_A = [1.0, 3.0, 6.0]


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:metrics",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """A cycle, a self-reference, an undefined Id and a scalar-valued expression are each refused
    whole with ValidationError, while a well-formed chain over the same data evaluates.
    """
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-mme-graph/")
    t0 = (datetime.now(timezone.utc) - timedelta(minutes=5)).replace(second=0, microsecond=0)
    cw.put_metric_data(Namespace=namespace, MetricData=[
        {"MetricName": "A", "Timestamp": t0 + timedelta(minutes=i), "Value": v}
        for i, v in enumerate(_A)
    ])
    m1 = {"Id": "m1", "ReturnData": False, "MetricStat": {
        "Metric": {"Namespace": namespace, "MetricName": "A"}, "Period": 60, "Stat": "Sum"}}
    window = dict(StartTime=t0, EndTime=t0 + timedelta(minutes=3), ScanBy="TimestampAscending")

    # Positive control: a well-formed chain e2 -> e1 -> m1 evaluates.
    good = [m1, {"Id": "e1", "Expression": "m1*2", "ReturnData": False},
            {"Id": "e2", "Expression": "e1+1"}]
    vals = _poll(lambda: _values(cw.get_metric_data(MetricDataQueries=good, **window)),
                 lambda v: v.get("e2") == [3.0, 7.0, 13.0])
    assert vals == {"e2": [3.0, 7.0, 13.0]}, f"well-formed chain returned {vals!r}"

    # why -> (queries, the exact ValidationError message)
    bad = {
        "two-node cycle": ([m1, {"Id": "e1", "Expression": "e2+m1"},
                            {"Id": "e2", "Expression": "e1+1", "ReturnData": False}],
                           "Circular dependency between expressions: e1 -> e2 -> e1"),
        "self reference": ([m1, {"Id": "e1", "Expression": "e1+m1"}],
                           "Circular dependency between expressions: e1 -> e1"),
        "undefined id": ([m1, {"Id": "e1", "Expression": "m9+m1"}],
                         "Error in expression 'e1': ID 'm9' not found"),
        "scalar result": ([m1, {"Id": "e1", "Expression": "SUM(m1)"}],
                          "Error in expression 'e1': The return value of the expression must be "
                          "TimeSeries or Array[TimeSeries]"),
    }
    for why, (queries, message) in bad.items():
        error = _error(lambda q=queries: cw.get_metric_data(MetricDataQueries=q, **window))
        assert error == ("ValidationError", message), (
            f"{why}: GetMetricData gave {error!r}, expected ValidationError {message!r}"
        )

    # The control still evaluates after the refusals: nothing global broke.
    again = _values(cw.get_metric_data(MetricDataQueries=good, **window))
    assert again == {"e2": [3.0, 7.0, 13.0]}, f"well-formed chain after refusals returned {again!r}"


def _values(resp):
    return {r["Id"]: r["Values"] for r in resp["MetricDataResults"]}


def _error(fn):
    """Return the (Code, Message) of a ClientError; raise if the call unexpectedly succeeds."""
    try:
        out = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"invalid expression graph was evaluated instead of refused: {out!r}")


def _poll(fn, ready, timeout_s=300, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = fn()
        if ready(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"published datapoints never became readable; last read {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
