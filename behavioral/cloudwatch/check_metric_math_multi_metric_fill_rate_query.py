"""metric-math-multi-metric-fill-rate-query."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "metric-math-multi-metric-fill-rate-query"
GROUP = 'metric-data'
SERVICES = ['cloudwatch']


# ===== helpers =====
def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _error(fn):
    """Call fn(); return the botocore Error dict if a ClientError is raised, else None."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    return None
# ===== end helpers =====


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Metric math over two series with a gap: binary arithmetic counts a missing operand as ZERO and
    keeps the timestamp (m1*m2 is 0 there), a bare reference does not, FILL() fills the gap and RATE()
    is per SECOND; dashboards and math alarms read these exact values."""
    cw = ctx.client("cloudwatch")
    ns = ctx.unique_name("sim2real-behav-cwprobe-ns-math-")
    name_a, name_b = "SeriesA", "SeriesB"
    now = datetime.now(timezone.utc)
    # Three aligned, closed 1-minute buckets in the recent past.
    base = now.replace(second=0, microsecond=0) - timedelta(minutes=8)
    t0, t1, t2 = base, base + timedelta(minutes=1), base + timedelta(minutes=2)
    start, end = base, base + timedelta(minutes=3)

    cw.put_metric_data(
        Namespace=ns,
        MetricData=[
            {"MetricName": name_a, "Timestamp": t0, "Value": 10.0, "Unit": "Count"},
            {"MetricName": name_a, "Timestamp": t1, "Value": 20.0, "Unit": "Count"},
            {"MetricName": name_a, "Timestamp": t2, "Value": 40.0, "Unit": "Count"},
            {"MetricName": name_b, "Timestamp": t0, "Value": 1.0, "Unit": "Count"},
            # deliberately NO datapoint for SeriesB at t1
            {"MetricName": name_b, "Timestamp": t2, "Value": 3.0, "Unit": "Count"},
        ],
    )

    def _stat(qid, metric_name, return_data):
        return {
            "Id": qid,
            "MetricStat": {
                "Metric": {"Namespace": ns, "MetricName": metric_name},
                "Period": 60,
                "Stat": "Sum",
            },
            "ReturnData": return_data,
        }

    def query(extra_queries, *, return_raw=False):
        queries = [_stat("m1", name_a, return_raw), _stat("m2", name_b, return_raw)]
        queries.extend(extra_queries)
        resp = cw.get_metric_data(
            MetricDataQueries=queries,
            StartTime=start,
            EndTime=end,
            ScanBy="TimestampAscending",
        )
        return {r["Id"]: r for r in resp["MetricDataResults"]}

    # Anchor: both raw series are ingested, with the intended gap in m2.
    raw = _poll_until(
        lambda: query([], return_raw=True),
        lambda res: len(res["m1"].get("Values", [])) == 3 and len(res["m2"].get("Values", [])) == 2,
        timeout_s=180,
        interval_s=5,
        description="SeriesA (3 points) and SeriesB (2 points, gap at t1) to become queryable",
    )
    assert raw["m1"]["Values"] == [10.0, 20.0, 40.0], (
        f"ScanBy=TimestampAscending must return SeriesA oldest-first as [10,20,40], got {raw['m1']['Values']}"
    )
    assert raw["m2"]["Values"] == [1.0, 3.0], f"SeriesB must have only its two points, got {raw['m2']['Values']}"
    assert raw["m2"]["Timestamps"] == [t0, t2], (
        f"SeriesB's timestamps must be exactly the two published buckets {[t0, t2]} -- the gap at "
        f"{t1} must not be materialised on the raw read path; got {raw['m2']['Timestamps']}"
    )
    # A raw MetricStat's default Label is the METRIC NAME (contrast with an expression's
    # default Label, which is its Id -- asserted below).
    assert raw["m1"]["Label"] == name_a, (
        f"a raw MetricStat result must default its Label to the metric name {name_a!r}, got "
        f"{raw['m1'].get('Label')!r}"
    )
    assert raw["m2"]["Label"] == name_b, raw["m2"].get("Label")

    res = query([
        {"Id": "e_sum", "Expression": "m1+m2", "ReturnData": True},
        {"Id": "e_mul", "Expression": "m1*m2", "ReturnData": True},
        {"Id": "e_sub", "Expression": "m2-m1", "ReturnData": True},
        {"Id": "e_m2", "Expression": "m2", "ReturnData": True},
        {"Id": "e_fill", "Expression": "FILL(m2, 0)", "ReturnData": True},
        {"Id": "e_both", "Expression": "m1+FILL(m2, 0)", "Label": "combined", "ReturnData": True},
        {"Id": "e_rate", "Expression": "RATE(m1)", "ReturnData": True},
    ])

    # --- Binary arithmetic substitutes ZERO for the missing operand and KEEPS the bucket ---
    e_sum = res["e_sum"]
    assert e_sum["Values"] == [11.0, 20.0, 43.0], (
        f"`m1+m2` must keep the bucket where m2 has no datapoint, counting the absent operand as "
        f"0 (10+0 = 20 at t1); expected [11.0, 20.0, 43.0], got {e_sum['Values']}"
    )
    assert e_sum["Timestamps"] == [t0, t1, t2], (
        f"no timestamp may be dropped for a missing operand; expected {[t0, t1, t2]}, got "
        f"{e_sum['Timestamps']}"
    )
    assert e_sum["StatusCode"] == "Complete", f"expected StatusCode=Complete, got {e_sum['StatusCode']}"
    # An expression with no caller Label defaults its Label to its own Id.
    assert e_sum["Label"] == "e_sum", (
        f"an expression's default Label is its Id, not the expression text; got {e_sum.get('Label')!r}"
    )

    # THE DISCRIMINATOR: multiplication separates "substitute 0" from "pass the present
    # operand through". Addition cannot -- 20+0 and a fall-through to m1 both give 20.
    e_mul = res["e_mul"]
    assert e_mul["Values"] == [10.0, 0.0, 120.0], (
        f"`m1*m2` must evaluate the missing t1 operand as 0, giving 20*0 = 0.0 -- an emulator "
        f"that falls through to the present operand yields 20.0 and an emulator that drops the "
        f"bucket yields two values; expected [10.0, 0.0, 120.0], got {e_mul['Values']}"
    )
    assert e_mul["Timestamps"] == [t0, t1, t2], e_mul["Timestamps"]

    # And the substitution is POSITIONAL: with the gap on the left of a subtraction the
    # result is 0-20, not 20-0 and not |20|.
    e_sub = res["e_sub"]
    assert e_sub["Values"] == [-9.0, -20.0, -37.0], (
        f"`m2-m1` must substitute 0 at m2's own position (0-20 = -20 at t1), got {e_sub['Values']}"
    )

    # --- A bare reference is NOT arithmetic, so it does NOT fill: this is the contrast that
    # makes the FILL leg below load-bearing at all ---
    e_m2 = res["e_m2"]
    assert e_m2["Values"] == [1.0, 3.0], (
        f"an expression that merely REFERENCES m2 must return m2's two real datapoints -- the "
        f"zero-substitution is a property of binary arithmetic, not of referencing; got "
        f"{e_m2['Values']}"
    )
    assert e_m2["Timestamps"] == [t0, t2], e_m2["Timestamps"]

    # --- FILL materialises the gap on a single series (2 values -> 3) ---
    e_fill = res["e_fill"]
    assert e_fill["Values"] == [1.0, 0.0, 3.0], (
        f"FILL(m2, 0) must materialise the missing t1 bucket as 0.0 inside the queried window; "
        f"expected [1.0, 0.0, 3.0], got {e_fill['Values']}"
    )
    assert e_fill["Timestamps"] == [t0, t1, t2], (
        f"FILL must emit all three bucket timestamps {[t0, t1, t2]}, got {e_fill['Timestamps']}"
    )
    assert len(e_fill["Values"]) == len(e_m2["Values"]) + 1, (
        "FILL must be observable as a CHANGE against the same series unfilled -- an emulator "
        f"implementing FILL as a no-op returns {e_m2['Values']} for both; got "
        f"{e_fill['Values']} vs {e_m2['Values']}"
    )

    # --- Nesting: a filled operand is accepted, and the caller's Label wins ---
    e_both = res["e_both"]
    assert e_both["Values"] == [11.0, 20.0, 43.0], (
        f"`m1+FILL(m2,0)` must keep all three timestamps with the gap contributing 0; expected "
        f"[11.0, 20.0, 43.0], got {e_both['Values']}"
    )
    # Verified: identical to `m1+m2`, because the arithmetic already counts the gap as 0. This
    # is asserted as an EQUALITY so that an emulator which drops the bucket in plain
    # arithmetic but honours FILL cannot pass both legs by disagreeing here.
    assert e_both["Values"] == e_sum["Values"], (
        "an explicit FILL(m2, 0) inside the sum must be redundant, since binary arithmetic "
        f"already substitutes 0; got {e_both['Values']} vs {e_sum['Values']}"
    )
    assert e_both["Label"] == "combined", (
        f"a caller-supplied Label must be echoed verbatim on the result, not replaced by the "
        f"expression text or the Id; got {e_both.get('Label')!r}"
    )

    # --- RATE is per SECOND, not per period ---
    e_rate = res["e_rate"]
    assert len(e_rate["Values"]) == 2, (
        f"RATE over 3 datapoints yields 2 differences (the first bucket has no predecessor), "
        f"got {e_rate['Values']}"
    )
    assert abs(e_rate["Values"][0] - (20.0 - 10.0) / 60.0) < 1e-9, (
        f"RATE(m1) must be the change divided by the elapsed SECONDS ((20-10)/60), not the raw "
        f"delta or a per-period value; got {e_rate['Values'][0]}"
    )
    assert abs(e_rate["Values"][1] - (40.0 - 20.0) / 60.0) < 1e-9, (
        f"expected the second RATE value to be (40-20)/60, got {e_rate['Values'][1]}"
    )
    # RATE drops the FIRST bucket, which is the one place a timestamp legitimately disappears.
    assert e_rate["Timestamps"] == [t1, t2], (
        f"RATE's values must be stamped with the LATER bucket of each pair {[t1, t2]}, got "
        f"{e_rate['Timestamps']}"
    )

    # A raw operand with ReturnData=False is omitted ENTIRELY -- not returned with an empty
    # Values list.
    assert set(res) == {"e_sum", "e_mul", "e_sub", "e_m2", "e_fill", "e_both", "e_rate"}, (
        f"ReturnData=False must omit the raw operand's whole MetricDataResult, so only the seven "
        f"expression ids may come back; got {sorted(res)}"
    )

    # --- Deep negative: an expression referencing an undefined id is rejected ---
    error = _error(lambda: query([{"Id": "e_bad", "Expression": "m1+m99", "ReturnData": True}]))
    assert error is not None, (
        "an expression referencing an id that is not in the request must be rejected, not "
        "silently evaluated as m1"
    )
    assert error.get("Code") == "ValidationError", (
        f"an unresolvable id is refused with ValidationError, got {error.get('Code')!r}"
    )
    assert error.get("Message") == "Error in expression 'e_bad': ID 'm99' not found", (
        f"the refusal must name the offending expression AND the unresolved id, got "
        f"{error.get('Message')!r}"
    )

    # --- Deep negative: a syntactically malformed expression is rejected ---
    error = _error(lambda: query([{"Id": "e_syntax", "Expression": "m1 +* m2", "ReturnData": True}]))
    assert error is not None, "a malformed metric-math expression must be rejected"
    assert error.get("Code") == "ValidationError", error
    # A PARSE failure, distinguished from the unresolved-id failure above: same code,
    # different message. Without this one error string would satisfy both negatives.
    assert error.get("Message") == "Error in expression 'e_syntax': Invalid syntax", (
        f"a malformed expression must be refused as a SYNTAX error, got {error.get('Message')!r}"
    )

    # --- Control: the valid expressions still evaluate after the rejections ---
    control = query([{"Id": "e_sum", "Expression": "m1+m2", "ReturnData": True}])
    assert control["e_sum"]["Values"] == [11.0, 20.0, 43.0], (
        f"the valid expression must be unaffected by the rejected requests, got {control['e_sum']['Values']}"
    )
    assert control["e_sum"]["Timestamps"] == [t0, t1, t2], control["e_sum"]["Timestamps"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
