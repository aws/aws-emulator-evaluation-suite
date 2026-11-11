"""metrics-math-and-emf-statistic-and-extended-statistic-fields-not-interchangeable-rejected."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "metrics-math-and-emf-statistic-and-extended-statistic-fields-not-interchangeable-rejected"
GROUP = "metric-statistics"
SERVICES = ["cloudwatch"]

_RAW = [float(i) for i in range(1, 101)]


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
    """GetMetricStatistics rejects p90 in Statistics and Average in ExtendedStatistics.

    Each name in its own field returns the right value, and GetMetricData's Stat takes both.
    """
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-mme-statfld/")
    ts = (datetime.now(timezone.utc) - timedelta(minutes=3)).replace(second=0, microsecond=0)
    cw.put_metric_data(Namespace=namespace, MetricData=[
        {"MetricName": "Dist", "Timestamp": ts, "Values": _RAW},
    ])
    base = dict(Namespace=namespace, MetricName="Dist", StartTime=ts,
                EndTime=ts + timedelta(seconds=60), Period=60)

    # Positive control first: each name in its own field returns the right value.
    avg_dps = _poll(lambda: cw.get_metric_statistics(Statistics=["Average"], **base)["Datapoints"])
    assert [d["Average"] for d in avg_dps] == [50.5], f"Average datapoints were {avg_dps!r}"
    p90_dps = cw.get_metric_statistics(ExtendedStatistics=["p90"], **base)["Datapoints"]
    assert len(p90_dps) == 1, f"ExtendedStatistics=['p90'] returned {p90_dps!r}"
    p90 = p90_dps[0]["ExtendedStatistics"]["p90"]
    assert 88.0 <= p90 <= 92.0, f"p90 of 1..100 was {p90!r}, expected ~90"
    assert "Average" not in p90_dps[0], (
        f"ExtendedStatistics-only request also returned a standard statistic: {p90_dps[0]!r}"
    )

    # Break exactly one thing each time: the field the name is placed in.
    code, message = _error(lambda: cw.get_metric_statistics(Statistics=["p90"], **base))
    assert code == "InvalidParameterValue", (
        f"Statistics=['p90'] gave {code!r}: {message!r}; expected InvalidParameterValue"
    )
    assert message == (
        "The parameter Statistics.member.1.<list element> must be a value in the set "
        "[SampleCount, Average, Sum, Minimum, Maximum]."
    ), message
    code, message = _error(lambda: cw.get_metric_statistics(ExtendedStatistics=["Average"], **base))
    assert code == "InvalidParameterValue", (
        f"ExtendedStatistics=['Average'] gave {code!r}: {message!r}; "
        "expected InvalidParameterValue"
    )
    assert message == (
        "The value Average for parameter ExtendedStatistics.member.1.<list element> is not supported."
    ), message

    # GetMetricData has ONE Stat field, and it takes both kinds of name.
    resp = cw.get_metric_data(
        MetricDataQueries=[
            {"Id": qid, "MetricStat": {"Metric": {"Namespace": namespace, "MetricName": "Dist"},
                                       "Period": 60, "Stat": stat}}
            for qid, stat in (("avg", "Average"), ("p90", "p90"))
        ],
        StartTime=ts, EndTime=ts + timedelta(seconds=60),
    )
    vals = {r["Id"]: r["Values"] for r in resp["MetricDataResults"]}
    assert vals.get("avg") == [50.5], f"GetMetricData Stat=Average returned {vals.get('avg')!r}"
    assert vals.get("p90") == [p90], (
        f"GetMetricData Stat=p90 returned {vals.get('p90')!r}; GetMetricStatistics said {p90!r}"
    )


def _error(fn):
    """Return (Error.Code, Error.Message) of a ClientError; raise if the call unexpectedly succeeds."""
    try:
        out = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"call was expected to be refused but succeeded: {out!r}")


def _poll(fn, timeout_s=300, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = fn()
        if last:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"published datapoints never became readable; last read {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
