"""unit-is-part-of-a-datapoints-read-identity."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "unit-is-part-of-a-datapoints-read-identity"
GROUP = "metric-data"
SERVICES = ["cloudwatch"]

#: Every subset of these values has a distinct sum, so no mix of units can pass for another.
_BYTES_V = 100.0
_KILOBYTES_V = 7.0
_NONE_V = 3.0

_STABLE_WINDOW_S = 5
_HOLD_S = 5


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until_stable(probe, *, window_s, timeout_s, interval_s=1, description="reading", ctx=None):
    """Return probe()'s value once two readings >= window_s apart are EQUAL and non-empty.

    An empty reading resets the anchor, so this can never "stabilise" on absence.
    """
    deadline = time.monotonic() + timeout_s
    anchor, anchor_t, last = None, 0.0, None
    while time.monotonic() < deadline:
        last = probe()
        now = time.monotonic()
        if not last:
            anchor, anchor_t = None, 0.0
        elif last != anchor:
            anchor, anchor_t = last, now
        elif now - anchor_t >= window_s:
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description} to hold one value: the run budget ended first; not graded")
    raise AssertionError(
        f"{description} never held one value for {window_s}s within {timeout_s}s; "
        f"last reading was {last!r}"
    )


def _assert_stays(probe, expected, *, hold_s, interval_s=1, description="reading"):
    """Assert probe() == expected continuously for hold_s -- absence proven, not just observed."""
    deadline = time.monotonic() + hold_s
    while True:
        got = probe()
        assert got == expected, (
            f"{description} became {got!r}, expected it to stay {expected!r} for {hold_s}s"
        )
        if time.monotonic() >= deadline:
            return
        time.sleep(interval_s)


def _error_code(fn):
    """The AWS (Error.Code, Error.Message) raised by fn(); raises if fn() succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected an AWS error, but the call succeeded with {result!r}")


@tags(
    "axis:rejection",
    "cap:c2",
    "concern:data-plane",
    "concern:metrics",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """`Unit` is part of a datapoint's read identity but not a metric's: three units on one metric
    read as three unconverted series, unpublished units read empty, invalid units are rejected,
    and ListMetrics still lists one metric."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-behav-cwunit-ns-")
    metric = "Payload"
    dims = [{"Name": "Probe", "Value": "unit-identity"}]

    # A closed whole-minute bucket three minutes back: no partial period can move underneath the
    # exact-value assertions.
    bucket = datetime.now(timezone.utc).replace(second=0, microsecond=0) - timedelta(minutes=3)
    cw.put_metric_data(Namespace=namespace, MetricData=[
        {"MetricName": metric, "Dimensions": dims, "Timestamp": bucket,
         "Value": _BYTES_V, "Unit": "Bytes"},
        {"MetricName": metric, "Dimensions": dims, "Timestamp": bucket,
         "Value": _KILOBYTES_V, "Unit": "Kilobytes"},
        {"MetricName": metric, "Dimensions": dims, "Timestamp": bucket,
         "Value": _NONE_V, "Unit": "None"},
    ])
    # A custom metric namespace has no delete API, so nothing is registered for cleanup.

    start = bucket - timedelta(minutes=2)
    end = bucket + timedelta(minutes=5)

    def _gms(unit=None):
        kwargs = {
            "Namespace": namespace, "MetricName": metric, "Dimensions": dims,
            "StartTime": start, "EndTime": end, "Period": 60,
            "Statistics": ["Sum", "SampleCount"],
        }
        if unit is not None:
            kwargs["Unit"] = unit
        return cw.get_metric_statistics(**kwargs)["Datapoints"]

    def _gmd(unit=None):
        stat = {
            "Metric": {"Namespace": namespace, "MetricName": metric, "Dimensions": dims},
            "Period": 60, "Stat": "Sum",
        }
        if unit is not None:
            stat["Unit"] = unit
        return cw.get_metric_data(
            MetricDataQueries=[{"Id": "q", "MetricStat": stat}], StartTime=start, EndTime=end,
        )["MetricDataResults"][0]

    def _one(unit):
        dps = _gms(unit)
        assert len(dps) == 1, (
            f"GetMetricStatistics with Unit={unit!r} returned {len(dps)} datapoints, expected "
            f"exactly 1: {dps!r}"
        )
        return dps[0]

    # --- the three unit-selected series, behind a stability requirement ------------------- #
    def _snapshot():
        per_unit = tuple(
            tuple(sorted((d["Unit"], d["Sum"], d["SampleCount"]) for d in _gms(u)))
            for u in ("Bytes", "Kilobytes", "None")
        )
        return per_unit if all(per_unit) else None

    stable = _poll_until_stable(
        _snapshot, window_s=_STABLE_WINDOW_S, timeout_s=_budget_s(ctx, 180.0), ctx=ctx,
        description=f"the three unit-selected series of {namespace}/{metric}",
    )
    assert stable == (
        (("Bytes", _BYTES_V, 1.0),),
        (("Kilobytes", _KILOBYTES_V, 1.0),),
        (("None", _NONE_V, 1.0),),
    ), (
        f"the three unit-selected reads stabilised at {stable!r}; each Unit must resolve to its "
        f"own datapoint carrying exactly the value published under that unit"
    )

    by_bytes = _one("Bytes")
    assert by_bytes["Sum"] == _BYTES_V, (
        f"Unit='Bytes' read Sum={by_bytes['Sum']!r}, expected {_BYTES_V} -- only the datum "
        f"published as Bytes, not the union {_BYTES_V + _KILOBYTES_V + _NONE_V}"
    )
    assert by_bytes["SampleCount"] == 1.0, (
        f"Unit='Bytes' read SampleCount={by_bytes['SampleCount']!r}, expected 1.0 -- one of the "
        f"three datums carries that unit"
    )
    assert by_bytes["Unit"] == "Bytes", f"datapoint Unit echoed {by_bytes['Unit']!r}"

    by_kb = _one("Kilobytes")
    assert by_kb["Sum"] == _KILOBYTES_V, (
        f"Unit='Kilobytes' read Sum={by_kb['Sum']!r}, expected {_KILOBYTES_V}. CloudWatch does "
        f"NO unit conversion: {_KILOBYTES_V} Kilobytes must not be normalised to "
        f"{_KILOBYTES_V * 1024} Bytes, and it must not appear in the Bytes series"
    )
    assert by_kb["Unit"] == "Kilobytes", f"datapoint Unit echoed {by_kb['Unit']!r}"

    by_none = _one("None")
    assert by_none["Sum"] == _NONE_V, (
        f"Unit='None' read Sum={by_none['Sum']!r}, expected {_NONE_V} -- 'None' is a real unit "
        f"value and its own storage bucket, not a wildcard"
    )
    assert by_none["Unit"] == "None", f"datapoint Unit echoed {by_none['Unit']!r}"

    # --- omitting Unit does NOT aggregate: it returns one datapoint PER unit --------------- #
    # CloudWatch returns three datapoints at the same timestamp, one per published unit.
    unitless = _gms()
    assert len(unitless) == 3, (
        f"GetMetricStatistics with no Unit returned {len(unitless)} datapoints, expected 3 -- "
        f"one per published unit, at one timestamp, NOT a single aggregate: {unitless!r}"
    )
    assert {d["Timestamp"] for d in unitless} == {d["Timestamp"] for d in _gms("Bytes")}, (
        f"the three unitless datapoints must share the one published minute bucket, got "
        f"{sorted(d['Timestamp'].isoformat() for d in unitless)!r}"
    )
    assert sorted((d["Unit"], d["Sum"], d["SampleCount"]) for d in unitless) == sorted([
        ("Bytes", _BYTES_V, 1.0), ("Kilobytes", _KILOBYTES_V, 1.0), ("None", _NONE_V, 1.0),
    ]), (
        f"the unitless read returned {sorted((d['Unit'], d['Sum']) for d in unitless)!r}; each "
        f"datapoint must carry its own unit and its own value, unsummed and unconverted"
    )

    # --- both read paths see one storage ---------------------------------------------------- #
    for unit, want in (("Bytes", _BYTES_V), ("Kilobytes", _KILOBYTES_V), ("None", _NONE_V)):
        res = _gmd(unit)
        assert res["StatusCode"] == "Complete", (
            f"GetMetricData with MetricStat.Unit={unit!r} reported "
            f"{res['StatusCode']!r}, expected 'Complete'"
        )
        assert res["Values"] == [want], (
            f"GetMetricData with MetricStat.Unit={unit!r} returned {res['Values']!r}, expected "
            f"[{want}] -- the same selection GetMetricStatistics made over the same storage"
        )

    # --- the catalogue asymmetry ----------------------------------------------------------- #
    def _catalogue():
        out, token = [], None
        while True:
            kwargs = {"Namespace": namespace}
            if token:
                kwargs["NextToken"] = token
            page = cw.list_metrics(**kwargs)
            out.extend(page["Metrics"])
            token = page.get("NextToken")
            if not token:
                return out

    listed = _poll_until_stable(
        lambda: tuple(sorted(
            (m["MetricName"], tuple(sorted((d["Name"], d["Value"]) for d in m["Dimensions"])))
            for m in _catalogue()
        )),
        window_s=_STABLE_WINDOW_S, timeout_s=_budget_s(ctx, 180.0), ctx=ctx,
        description=f"ListMetrics catalogue for namespace {namespace!r}",
    )
    assert listed == ((metric, (("Probe", "unit-identity"),)),), (
        f"ListMetrics returned {listed!r}, expected exactly one entry. Unit is part of a "
        f"DATAPOINT's read identity and NOT of a metric's catalogue identity: three units must "
        f"not become three catalogue entries. This asymmetry is the assertion that separates a "
        f"correct implementation from one that keys everything uniformly"
    )

    # --- failure arm: units never published resolve to nothing, and stay nothing ----------- #
    # 'Terabytes' and 'Count' are both VALID CloudWatch units, so an empty result here is a
    # storage-key decision and not input validation.
    _assert_stays(
        lambda: {u: _gms(u) for u in ("Terabytes", "Percent", "Count")},
        {u: [] for u in ("Terabytes", "Percent", "Count")},
        hold_s=_HOLD_S,
        description=(
            "reads for the valid-but-never-published units Terabytes/Percent/Count on a metric "
            "that does hold data under three other units"
        ),
    )
    for unit in ("Terabytes", "Percent", "Count"):
        res = _gmd(unit)
        assert res["StatusCode"] == "Complete" and res["Values"] == [], (
            f"GetMetricData with MetricStat.Unit={unit!r} returned {res['Values']!r} with "
            f"StatusCode {res['StatusCode']!r}; a never-published unit is an EMPTY successful "
            f"result on this path too, not an error and not the other units' data"
        )

    # --- failure arm: a string that is not a unit at all is rejected, per read path -------- #
    gms_code, gms_message = _error_code(lambda: _gms("Furlongs"))
    assert gms_code == "InvalidParameterValue", (
        f"GetMetricStatistics with Unit='Furlongs' raised {gms_code!r}, expected "
        f"'InvalidParameterValue' -- the unit enum is validated server-side: {gms_message!r}"
    )
    assert gms_message == (
        "The parameter Unit must be a value in the set [ Megabits, Terabits, Gigabits, Count, Bytes, "
        "Gigabytes, Gigabytes/Second, Kilobytes, Kilobits/Second, Terabytes, Terabits/Second, "
        "Bytes/Second, Percent, Megabytes, Megabits/Second, Milliseconds, Microseconds, "
        "Kilobytes/Second, Gigabits/Second, Megabytes/Second, Bits, Bits/Second, Count/Second, "
        "Seconds, Kilobits, Terabytes/Second, None ]."
    ), gms_message
    gmd_code, gmd_message = _error_code(lambda: _gmd("Furlongs"))
    assert gmd_code == "ValidationError", (
        f"GetMetricData with MetricStat.Unit='Furlongs' raised {gmd_code!r}, expected "
        f"'ValidationError'. The two read paths validate the SAME enum through different "
        f"machinery and report it with different codes; an emulator that returns one code for "
        f"both has one validator where AWS has two: {gmd_message!r}"
    )
    assert gmd_message == (
        "1 validation error detected: Value at 'metricDataQueries.1.member.metricStat.unit' failed "
        "to satisfy constraint: Member must satisfy enum value set: [Gigabits/Second, Gigabits, "
        "Percent, Terabits, Bits, Kilobits, Megabytes/Second, Kilobytes, Megabits/Second, Terabytes, "
        "Bytes, Count, Gigabytes, Milliseconds, Count/Second, Gigabytes/Second, None, "
        "Terabytes/Second, Bytes/Second, Megabits, Kilobytes/Second, Megabytes, Microseconds, "
        "Kilobits/Second, Terabits/Second, Bits/Second, Seconds]"
    ), gmd_message

    # --- positive control, after every negative -------------------------------------------- #
    control = _one("Bytes")
    assert control["Sum"] == _BYTES_V, (
        f"after the rejected and empty reads, Unit='Bytes' read Sum={control['Sum']!r}, "
        f"expected {_BYTES_V} -- the stored datapoints are unchanged"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
