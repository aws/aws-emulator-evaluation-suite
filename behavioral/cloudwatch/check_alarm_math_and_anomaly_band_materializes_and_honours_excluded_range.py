"""alarm-math-and-anomaly-band-materializes-and-honours-excluded-range."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "alarm-math-and-anomaly-band-materializes-and-honours-excluded-range"
GROUP = "anomaly-detector"
SERVICES = ["cloudwatch"]

_BASELINE = (10.0, 10.5, 11.0)
_SPIKE = 1000.0
#: 10x above the baseline and 10x below the spike: a band trained WITH the spike reaches above it
#: (upper ~2484), a band trained without it stays far below (upper ~11.75).
_SPIKE_SHAPED = 100.0


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch_concepts.html
@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:metrics", "dp:api",
      "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A trained detector's ANOMALY_DETECTION_BAND has Low/High datapoints bracketing the baseline,
    an unexcluded spike widens it, ExcludedTimeRanges keeps the same spike out, and a metric
    without a detector gets an empty band.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutAnomalyDetector.html
    """
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealBehavAdBand")
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    spike_lo = now - timedelta(minutes=70)
    spike_hi = now - timedelta(minutes=40)

    def _seed(metric: str, spike: bool) -> None:
        points = []
        for i in range(1, 91):
            ts = now - timedelta(minutes=2 * i)
            value = _SPIKE if spike and spike_lo <= ts <= spike_hi else _BASELINE[i % 3]
            points.append({"MetricName": metric, "Timestamp": ts, "Value": value})
        for j in range(0, len(points), 20):
            cw.put_metric_data(Namespace=namespace, MetricData=points[j:j + 20])

    for metric, spike in (("A", False), ("B", True), ("C", True), ("D", False)):
        _seed(metric, spike)

    def _det(metric: str) -> dict:
        return {"Namespace": namespace, "MetricName": metric, "Stat": "Average"}

    def _band(metric: str) -> dict[str, list]:
        res = cw.get_metric_data(
            MetricDataQueries=[
                {"Id": "m1", "MetricStat": {"Metric": {"Namespace": namespace, "MetricName": metric},
                                            "Period": 60, "Stat": "Average"}, "ReturnData": True},
                {"Id": "ad1", "Expression": "ANOMALY_DETECTION_BAND(m1, 2)", "ReturnData": True},
            ],
            StartTime=now - timedelta(hours=3), EndTime=now + timedelta(minutes=30))
        return {r["Label"]: r for r in res["MetricDataResults"] if r["Id"] == "ad1"}

    def _detectors() -> dict[str, str]:
        out, token = {}, None
        while True:
            page = cw.describe_anomaly_detectors(Namespace=namespace,
                                                 **({"NextToken": token} if token else {}))
            for d in page["AnomalyDetectors"]:
                out[d["SingleMetricAnomalyDetector"]["MetricName"]] = d["StateValue"]
            token = page.get("NextToken")
            if not token:
                return out

    # --- effect-absent baseline: no detector, no band, and the query creates none -------------- #
    # D (no detector) proves A's datapoints come from A's detector, not from the query.
    empty = _band("D")
    assert sorted(empty) == ["D High", "D Low"], (
        f"the band query on detector-less D returned series labelled {sorted(empty)!r}; expected "
        f"the Low/High pair"
    )
    assert all(r["Values"] == [] for r in empty.values()), (
        f"D has no anomaly detector, yet its band has datapoints: "
        f"{ {k: len(v['Values']) for k, v in empty.items()}!r}"
    )

    for metric in ("A", "B", "C"):
        # Registered before the create: a partial create still leaves a detector to remove.
        ctx.on_cleanup(lambda m=metric: cw.delete_anomaly_detector(SingleMetricAnomalyDetector=_det(m)))
    cw.put_anomaly_detector(SingleMetricAnomalyDetector=_det("A"))
    cw.put_anomaly_detector(
        SingleMetricAnomalyDetector=_det("B"),
        Configuration={"ExcludedTimeRanges": [{"StartTime": spike_lo - timedelta(minutes=1),
                                               "EndTime": spike_hi + timedelta(minutes=1)}]})
    cw.put_anomaly_detector(SingleMetricAnomalyDetector=_det("C"))
    assert "D" not in _detectors(), "querying D's band created an anomaly detector for D"

    def _all_bands():
        return {m: _band(m) for m in ("A", "B", "C")}

    bands = _poll_until(
        _all_bands,
        lambda bs: all(len(bs[m].get(f"{m} {s}", {}).get("Values", [])) > 0
                       for m in bs for s in ("Low", "High")),
        # Training takes several minutes.
        timeout_s=_budget_s(ctx, 1200.0), ctx=ctx, interval_s=2.0,
        description="the A, B and C detectors trained and their bands returned datapoints",
    )

    # --- A: the band is materialised, well-formed, and brackets the baseline -------------------- #
    low, high = bands["A"]["A Low"], bands["A"]["A High"]
    lows = dict(zip(low["Timestamps"], low["Values"]))
    highs = dict(zip(high["Timestamps"], high["Values"]))
    shared = sorted(set(lows) & set(highs))
    assert shared, f"A's Low and High series share no timestamp: {sorted(lows)!r} / {sorted(highs)!r}"
    for ts in shared:
        assert highs[ts] > lows[ts], (
            f"at {ts.isoformat()} A's band is inverted: Low {lows[ts]!r} >= High {highs[ts]!r}"
        )
        assert lows[ts] <= _BASELINE[1] <= highs[ts], (
            f"at {ts.isoformat()} A's band [{lows[ts]!r}, {highs[ts]!r}] excludes the baseline "
            f"centre {_BASELINE[1]} it was trained on"
        )

    # --- C (positive control): an unexcluded spike widens the band ----------------------------- #
    c_top = max(bands["C"]["C High"]["Values"])
    assert c_top > _SPIKE_SHAPED, (
        f"C was trained over a {_SPIKE} spike with no exclusion, yet its band tops out at "
        f"{c_top!r}; without a spike-shaped control B's result below means nothing"
    )

    # --- B: the identical spike inside ExcludedTimeRanges does not shape the band --------------- #
    b_top = max(bands["B"]["B High"]["Values"])
    a_top = max(highs.values())
    assert b_top < _SPIKE_SHAPED, (
        f"B excluded its spike window, yet its band reaches {b_top!r} (C's unexcluded band: "
        f"{c_top!r}, A's clean band: {a_top!r}) -- the excluded data was trained on"
    )

    # the D control still has no detector and no band after everything else trained
    assert "D" not in _detectors(), "D acquired an anomaly detector it was never given"
    assert all(r["Values"] == [] for r in _band("D").values()), (
        "detector-less D's band gained datapoints while A/B/C trained"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, timeout_s, interval_s, description, ctx=None):
    """Poll probe() until predicate(result); AssertionError on exhaustion."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            last = probe()
        except ClientError as exc:
            last = exc.response["Error"]
        else:
            if predicate(last):
                return last
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"{description}: the run budget ended first; not graded")
            raise AssertionError(f"{description} did not happen within {timeout_s}s; "
                                 f"last observation {last!r}")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
