"""get-metric-data-dynamic-label-is-resolved-server-side."""
from __future__ import annotations

# What the check relies on:
#   - GetMetricData resolves dynamic label placeholders; LabelOptions exists on GetMetricData to
#     control time-based label rendering.
#   - ${DATAPOINT_COUNT} renders as the plain decimal count of returned values. Number FORMATTING
#     is deliberately not pinned anywhere else in this file -- CloudWatch abbreviates large
#     numbers ('1.2k') and the counts here are single digits to stay clear of that.
#   - ${LABEL} expands to the default label, which for a single metric is the metric name.
#   - LabelOptions.Timezone changes a ${MAX_TIME} rendering. The check asserts only that two
#     different offsets produce DIFFERENT strings for the same data -- no format is pinned.
#   - A label may carry several placeholders in one string (docs say up to six) and ${LABEL} may
#     appear at most once.
#   - Ingest latency: 180s.

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "get-metric-data-dynamic-label-is-resolved-server-side"
GROUP = "metric-data"
SERVICES = ["cloudwatch"]

#: Three distinct values in three distinct minutes, so ${MIN}/${MAX}/${SUM} are three different
#: numbers and ${MAX_TIME} names one specific minute.
_SERIES = [13.0, 41.0, 29.0]
_PLACEHOLDERS = ("${MIN}", "${MAX}", "${SUM}", "${DATAPOINT_COUNT}", "${LABEL}")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """A dynamic label is computed by the server from the data it is about to return.

    No placeholder survives, count/max/sum/${LABEL} match the data, Timezone changes ${MAX_TIME}."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealDynLabelNs")
    metric = "LabelledSeries"
    base = datetime.now(timezone.utc).replace(second=0, microsecond=0) - timedelta(minutes=6)
    stamps = [base + timedelta(minutes=i) for i in range(len(_SERIES))]

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {"MetricName": metric, "Timestamp": ts, "Value": v, "Unit": "Count"}
            for ts, v in zip(stamps, _SERIES)
        ],
    )

    template = "min ${MIN} max ${MAX} sum ${SUM} n ${DATAPOINT_COUNT} of ${LABEL}"

    def _fetch(label: str, timezone_offset: str | None) -> dict:
        kwargs = dict(
            MetricDataQueries=[
                {
                    "Id": "m1",
                    "Label": label,
                    "MetricStat": {
                        "Metric": {"Namespace": namespace, "MetricName": metric},
                        "Period": 60,
                        "Stat": "Maximum",
                    },
                    "ReturnData": True,
                }
            ],
            StartTime=base,
            EndTime=base + timedelta(minutes=len(_SERIES)),
            ScanBy="TimestampAscending",
        )
        if timezone_offset is not None:
            kwargs["LabelOptions"] = {"Timezone": timezone_offset}
        results = cw.get_metric_data(**kwargs)["MetricDataResults"]
        assert len(results) == 1, (
            f"a single-metric GetMetricData query returned {len(results)} results {results!r}, "
            f"expected exactly 1"
        )
        return results[0]

    result = _poll_until(
        lambda: _fetch(template, None),
        # Hard-subscripted: GetMetricData always returns Values, and a `.get(..., [])` here would
        # supply exactly the empty value the poll exists to wait past.
        lambda r: len(r["Values"]) == len(_SERIES),
        timeout_s=180.0,
        interval_s=5.0,
        description=(
            f"all {len(_SERIES)} backdated datapoints queryable in namespace {namespace!r}, so the "
            f"dynamic label is computed over the complete series"
        ),
    )

    values = [float(v) for v in result["Values"]]
    assert sorted(values) == sorted(_SERIES), (
        f"the query returned Values {values!r}, expected this check's published series "
        f"{_SERIES!r}; the label assertions below are only meaningful over the right data"
    )
    label = result["Label"]

    # --- the echo detector ------------------------------------------------------------------- #
    surviving = [p for p in _PLACEHOLDERS if p in label]
    assert surviving == [], (
        f"the returned Label is {label!r} and still contains the unresolved placeholders "
        f"{surviving!r}; a dynamic label is resolved by the server from the data it is returning, "
        f"so a target that stored and echoed the request's Label string is detected here and "
        f"nowhere else in this suite"
    )
    assert "${" not in label, (
        f"the returned Label is {label!r} and still contains a '${{' sequence, so at least one "
        f"placeholder was not resolved"
    )

    # --- the count is derived from this very response ----------------------------------------- #
    expected_count = str(len(values))
    assert f"n {expected_count} of " in label, (
        f"the returned Label is {label!r}; the template rendered ${{DATAPOINT_COUNT}} between "
        f"'n ' and ' of ', and the response itself carries {len(values)} values, so it must read "
        f"'n {expected_count} of '. This is the one number in the label whose formatting is "
        f"unambiguous -- CloudWatch abbreviates large numbers, and {len(values)} is a single digit"
    )

    # --- ${LABEL} expands to the default label, which names the metric ------------------------ #
    assert metric in label, (
        f"the returned Label is {label!r} and does not contain the metric name {metric!r}; "
        f"${{LABEL}} expands to the default label for the series, which for a single metric with "
        f"no dimensions is its name"
    )

    # --- the numbers in the label are THIS series's numbers ----------------------------------- #
    for name, number in (("max", max(_SERIES)), ("sum", sum(_SERIES))):
        digits = str(int(number))
        assert digits in label, (
            f"the returned Label is {label!r} and does not contain {digits!r}, the decimal digits "
            f"of the series {name} ({number!r}); the placeholder resolved to some number but not "
            f"to the one derived from the returned Values {values!r}"
        )
    assert str(int(min(_SERIES))) in label, (
        f"the returned Label is {label!r} and does not contain {int(min(_SERIES))!r}, the series "
        f"minimum"
    )

    # --- LabelOptions.Timezone changes a time-based rendering, and only that ------------------- #
    time_template = "peak at ${MAX_TIME} for ${LABEL}"
    utc = _fetch(time_template, "+0000")["Label"]
    shifted = _fetch(time_template, "+0530")["Label"]
    for rendered, offset in ((utc, "+0000"), (shifted, "+0530")):
        assert "${" not in rendered, (
            f"the Label rendered under Timezone={offset!r} is {rendered!r} and still contains an "
            f"unresolved placeholder"
        )
        assert metric in rendered, (
            f"the Label rendered under Timezone={offset!r} is {rendered!r} and does not name the "
            f"metric {metric!r}"
        )
    assert utc != shifted, (
        f"the same ${{MAX_TIME}} label over the same data rendered identically under Timezone "
        f"'+0000' and '+0530': {utc!r}. LabelOptions.Timezone exists to shift exactly this "
        f"rendering, so identical strings mean the option was accepted and discarded"
    )
    assert utc.startswith("peak at ") and shifted.startswith("peak at "), (
        f"the two renderings are {utc!r} and {shifted!r}; the literal prefix of the template must "
        f"survive both, or the label is being fabricated rather than rendered"
    )
    assert utc.endswith(f"for {metric}") and shifted.endswith(f"for {metric}"), (
        f"the two renderings are {utc!r} and {shifted!r}; only the ${{MAX_TIME}} portion may "
        f"differ between two timezone offsets, so the trailing 'for <label>' must be identical in "
        f"both -- this is what stops 'returns two different strings' from satisfying the "
        f"assertion above"
    )

    # --- control: the first template still renders after the timezone calls ------------------- #
    again = _fetch(template, None)["Label"]
    assert "${" not in again and metric in again, (
        f"after the LabelOptions calls the original template rendered {again!r}; it must still "
        f"resolve, or the earlier success was not about label rendering"
    )


# ===== helpers =====
def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Poll probe() until predicate(result); FAIL on exhaustion, never skip."""
    deadline = time.monotonic() + timeout_s
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
