"""cw-get-metric-data-math-expression-is-computed-server-side."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "cw-get-metric-data-math-expression-is-computed-server-side"
GROUP = "metric-math"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """GetMetricData evaluates metric math server-side over data this check just wrote.

    An absent operand reads as 0 where another operand has a datapoint, and yields none where all do."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealDepthMathNs")
    t = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    start = t - timedelta(minutes=2)
    end = t + timedelta(minutes=2)

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {"MetricName": "Numerator", "Timestamp": t, "Value": 4.0, "Unit": "Count"},
            {"MetricName": "Denominator", "Timestamp": t, "Value": 1.0, "Unit": "Count"},
        ],
    )

    def _stat(metric_name: str, mid: str, return_data: bool) -> dict:
        return {
            "Id": mid,
            "ReturnData": return_data,
            "MetricStat": {
                "Metric": {"Namespace": namespace, "MetricName": metric_name},
                "Period": 60,
                "Stat": "Maximum",
            },
        }

    raw_queries = [_stat("Numerator", "m1", True), _stat("Denominator", "m2", True)]

    def _raw() -> dict[str, list[float]]:
        resp = cw.get_metric_data(
            MetricDataQueries=raw_queries, StartTime=start, EndTime=end
        )
        return {r["Id"]: r["Values"] for r in resp["MetricDataResults"]}

    raw = _poll_until(
        _raw,
        lambda by_id: len(by_id.get("m1", [])) > 0 and len(by_id.get("m2", [])) > 0,
        timeout_s=180.0,
        interval_s=5.0,
        description="both freshly published series became readable via GetMetricData",
    )
    assert raw["m1"] == [4.0], f"the raw Numerator series read back as {raw['m1']!r}, expected [4.0]"
    assert raw["m2"] == [1.0], f"the raw Denominator series read back as {raw['m2']!r}, expected [1.0]"

    # One request: the two source series (ReturnData False so only the math comes back), a ghost
    # series that was never written, and four expressions over them.
    resp = cw.get_metric_data(
        MetricDataQueries=[
            _stat("Numerator", "m1", False),
            _stat("Denominator", "m2", False),
            _stat("NeverWritten", "mghost", False),
            {"Id": "e1", "Expression": "m1 + m2", "ReturnData": True},
            {"Id": "e2", "Expression": "m1 / m2 * 100", "ReturnData": True},
            {"Id": "e3", "Expression": "SUM([m1,m2])", "ReturnData": True},
            {"Id": "e4", "Expression": "m1 + mghost", "ReturnData": True},
            {"Id": "e5", "Expression": "m1 * mghost", "ReturnData": True},
            {"Id": "e6", "Expression": "mghost + mghost", "ReturnData": True},
        ],
        StartTime=start,
        EndTime=end,
    )
    by_id = {r["Id"]: r for r in resp["MetricDataResults"]}
    assert set(by_id) == {"e1", "e2", "e3", "e4", "e5", "e6"}, (
        f"ReturnData=False sources still came back: got ids {sorted(by_id)!r}"
    )

    assert by_id["e1"]["Values"] == [5.0], (
        f"m1 + m2 over 4.0 and 1.0 returned {by_id['e1']['Values']!r}, expected [5.0] -- the "
        f"server did not perform the addition"
    )
    assert by_id["e2"]["Values"] == [400.0], (
        f"m1 / m2 * 100 over 4.0 and 1.0 returned {by_id['e2']['Values']!r}, expected [400.0]"
    )
    assert by_id["e3"]["Values"] == [5.0], (
        f"SUM([m1,m2]) over 4.0 and 1.0 returned {by_id['e3']['Values']!r}, expected [5.0]"
    )
    # The absent-operand rule on real AWS: a binary operator whose OTHER side has a datapoint at
    # T coerces the absent side to 0; a timestamp at which EVERY operand is absent emits no
    # datapoint at all. The three legs below are what separate those two rules from each other
    # and from "absent operand ignored".
    assert by_id["e4"]["Values"] == [4.0], (
        f"m1 + mghost over a never-written mghost returned {by_id['e4']['Values']!r}, expected "
        f"[4.0]: the absent operand is coerced to 0, so the sum is m1 itself"
    )
    assert by_id["e5"]["Values"] == [0.0], (
        f"m1 * mghost returned {by_id['e5']['Values']!r}, expected [0.0]. This is the leg that "
        f"pins the rule: if the absent operand were IGNORED rather than coerced to 0 the product "
        f"would be 4.0, and if the expression were dropped it would be []"
    )
    assert by_id["e6"]["Values"] == [], (
        f"mghost + mghost returned {by_id['e6']['Values']!r}, expected []: the 0-coercion applies "
        f"only where some operand HAS a datapoint, so an all-absent timestamp emits nothing at all "
        f"rather than 0.0"
    )
    assert by_id["e6"]["StatusCode"] == "Complete", (
        f"the all-absent expression reported StatusCode {by_id['e6']['StatusCode']!r}; an empty "
        f"result is a complete answer, not a partial one"
    )
    assert by_id["e1"]["StatusCode"] == "Complete", f"{by_id['e1']['StatusCode']!r}"
    assert by_id["e1"]["Timestamps"] == sorted(by_id["e1"]["Timestamps"], reverse=True), (
        f"GetMetricData must return TimestampDescending by default, got "
        f"{by_id['e1']['Timestamps']!r}"
    )
    assert len(by_id["e1"]["Timestamps"]) == len(by_id["e1"]["Values"]), (
        f"{len(by_id['e1']['Timestamps'])!r} timestamps for "
        f"{len(by_id['e1']['Values'])!r} values"
    )


# ===== helpers =====
def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Poll probe() until predicate(result); FAIL on exhaustion.

    Deliberately raises rather than returning the last value: 'the datapoint never came back' is
    the only interesting failure on a metric-read surface.
    """
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} did not happen within {timeout_s}s; last observation {last!r}"
            )
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
