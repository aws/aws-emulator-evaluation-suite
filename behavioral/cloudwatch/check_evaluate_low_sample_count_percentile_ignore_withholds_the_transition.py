"""evaluate-low-sample-count-percentile-ignore-withholds-the-transition."""
from __future__ import annotations

# What the check relies on:
#   - One raw sample per 60s period is "too few data points to be statistically significant" for
#     a p50 alarm, so the EvaluateLowSampleCountPercentile='ignore' twin does not transition (see
#     the CloudWatch user guide, "Percentile-based CloudWatch alarms and low data samples").
#   - 300 samples in a period IS enough for a p50 alarm to be evaluated under 'ignore'.
#   - The withheld twin's state while data is sparse is INSUFFICIENT_DATA, the state it starts in:
#     'the alarm state does not change'.
#   - DescribeAlarmHistory StateUpdate Timestamps order across two alarms in one account/region.
#   - Timing: 360s for the 'evaluate' twin's first transition and 420s for the repaired 'ignore'
#     twin, inside a 900s suite ceiling.

import json
import time
from datetime import datetime, timezone

from behavioral_harness import tags

CHECK = "evaluate-low-sample-count-percentile-ignore-withholds-the-transition"
GROUP = "evaluation"
SERVICES = ["cloudwatch"]

_THRESHOLD = 10.0
_SPARSE_VALUE = 100.0  # one sample per period, far above the threshold
#: The repair: a genuinely populated distribution. 150 is the per-datum Values/Counts limit, so two
#: data are used. Every value is above the threshold, so p50 still breaches.
_DENSE_VALUES = [100.0 + i for i in range(150)]
_DENSE_COUNT_PER_VALUE = 1.0
_DENSE_SAMPLES = 2 * len(_DENSE_VALUES) * _DENSE_COUNT_PER_VALUE


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:negative-delivery", "cap:c4", "concern:data-plane", "concern:metrics", "dp:api",
      "plane:data", "timing:real-time")
def run(ctx) -> None:
    """EvaluateLowSampleCountPercentile='ignore' withholds a transition the twin makes.

    On one sample per period only the 'evaluate' twin alarms; with 300 samples 'ignore' alarms later."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealLowSampleNs")
    metric = "SparseLatency"
    evaluate_name = ctx.unique_name("sim2real-lowsample-evaluate-")
    ignore_name = ctx.unique_name("sim2real-lowsample-ignore-")

    def _minute() -> datetime:
        return datetime.now(timezone.utc).replace(second=0, microsecond=0)

    def _publish_sparse() -> None:
        """Exactly ONE sample in the current period. Republishing inside a minute would raise the
        sample count, which is the variable under test, so the timestamp is the minute floor and
        the caller is responsible for calling this at most once per minute."""
        cw.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": metric,
                    "Timestamp": _minute(),
                    "Value": _SPARSE_VALUE,
                    "Unit": "Milliseconds",
                }
            ],
        )

    def _publish_dense() -> None:
        stamp = _minute()
        cw.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": metric,
                    "Timestamp": stamp,
                    "Values": _DENSE_VALUES,
                    "Counts": [_DENSE_COUNT_PER_VALUE] * len(_DENSE_VALUES),
                    "Unit": "Milliseconds",
                },
                {
                    "MetricName": metric,
                    "Timestamp": stamp,
                    "Values": _DENSE_VALUES,
                    "Counts": [_DENSE_COUNT_PER_VALUE] * len(_DENSE_VALUES),
                    "Unit": "Milliseconds",
                },
            ],
        )

    def _create(name: str, policy: str) -> None:
        cw.put_metric_alarm(
            AlarmName=name,
            Namespace=namespace,
            MetricName=metric,
            ExtendedStatistic="p50",
            Unit="Milliseconds",
            Period=60,
            EvaluationPeriods=1,
            DatapointsToAlarm=1,
            Threshold=_THRESHOLD,
            ComparisonOperator="GreaterThanThreshold",
            TreatMissingData="missing",
            EvaluateLowSampleCountPercentile=policy,
            ActionsEnabled=False,
            AlarmDescription=f"sim2real depth: EvaluateLowSampleCountPercentile={policy}",
            Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        )

    _publish_sparse()

    for name, policy in ((evaluate_name, "evaluate"), (ignore_name, "ignore")):
        _create(name, policy)
        ctx.on_cleanup(lambda n=name: cw.delete_alarms(AlarmNames=[n]))

    described = {"e": _describe(cw, evaluate_name), "i": _describe(cw, ignore_name)}
    assert described["e"]["EvaluateLowSampleCountPercentile"] == "evaluate", (
        f"the evaluate twin read back EvaluateLowSampleCountPercentile "
        f"{described['e'].get('EvaluateLowSampleCountPercentile')!r}, expected 'evaluate'"
    )
    assert described["i"]["EvaluateLowSampleCountPercentile"] == "ignore", (
        f"the ignore twin read back EvaluateLowSampleCountPercentile "
        f"{described['i'].get('EvaluateLowSampleCountPercentile')!r}, expected 'ignore'"
    )
    differing = {
        key
        for key in (
            "Namespace", "MetricName", "ExtendedStatistic", "Unit", "Period", "EvaluationPeriods",
            "DatapointsToAlarm", "Threshold", "ComparisonOperator", "TreatMissingData",
        )
        if described["e"].get(key) != described["i"].get(key)
    }
    assert not differing, (
        f"the two alarms differ in {sorted(differing)!r} as well as in "
        f"EvaluateLowSampleCountPercentile, so any divergence in state below cannot be attributed "
        f"to the low-sample-count policy"
    )
    for key, alarm in (("e", described["e"]), ("i", described["i"])):
        assert alarm["StateValue"] == "INSUFFICIENT_DATA", (
            f"the {key!r} twin started in {alarm['StateValue']!r}, expected INSUFFICIENT_DATA -- "
            f"every new CloudWatch alarm does, and beat 2 needs a known starting point"
        )

    # --- beat 1: the demonstrated control fires on the sparse series --------------------------- #
    last_sparse = [_minute()]

    def _sparse_tick() -> None:
        """Keep exactly one sample in each fresh period, and never two in the same one."""
        now = _minute()
        if now != last_sparse[0]:
            last_sparse[0] = now
            _publish_sparse()

    fired = _poll_until(
        lambda: _describe(cw, evaluate_name),
        lambda a: a["StateValue"] == "ALARM",
        timeout_s=360.0,
        interval_s=15.0,
        description=(
            f"the EvaluateLowSampleCountPercentile='evaluate' twin {evaluate_name!r} reached ALARM "
            f"on a one-sample-per-period p50 series above the threshold {_THRESHOLD}"
        ),
        on_iteration=_sparse_tick,
    )
    srd = json.loads(fired["StateReasonData"])
    window = srd["recentDatapoints"]
    assert len(window) == 1 and abs(float(window[0]) - _SPARSE_VALUE) < 1e-6, (
        f"the evaluate twin fired over recentDatapoints {window!r}; with one raw sample of "
        f"{_SPARSE_VALUE} in the period the p50 of that period IS {_SPARSE_VALUE}, so a different "
        f"value means the percentile was not computed from this check's data"
    )

    # --- beat 2: at that same instant, the ignore twin has done nothing ------------------------ #
    withheld = _describe(cw, ignore_name)
    assert withheld["StateValue"] == "INSUFFICIENT_DATA", (
        f"the EvaluateLowSampleCountPercentile='ignore' twin reports "
        f"{withheld['StateValue']!r} with reason {withheld.get('StateReason')!r} at the very "
        f"moment its 'evaluate' twin reached ALARM over the SAME datapoints. 'ignore' means the "
        f"alarm state does not change during periods with too few datapoints to be statistically "
        f"significant, and one sample per period is that case, so it must still be "
        f"INSUFFICIENT_DATA"
    )
    ignore_alarms_before = [i for i in _state_updates(cw, ignore_name) if _new_state(i) == "ALARM"]
    assert ignore_alarms_before == [], (
        f"the ignore twin's history already records {len(ignore_alarms_before)} ALARM transitions "
        f"{ignore_alarms_before!r}; a second, independent observable of the same absence -- the "
        f"DescribeAlarms snapshot could in principle have been read between a fire and a recovery, "
        f"the history cannot"
    )
    evaluate_fired_at = _first_alarm_timestamp(cw, evaluate_name)

    # --- beat 3: repair only the withheld thing -- the sample count -- and demand the transition #
    _publish_dense()
    repaired = _poll_until(
        lambda: _describe(cw, ignore_name),
        lambda a: a["StateValue"] == "ALARM",
        timeout_s=420.0,
        interval_s=15.0,
        description=(
            f"the 'ignore' twin {ignore_name!r} transitioned to ALARM once a "
            f"{int(_DENSE_SAMPLES)}-sample distribution made the period statistically "
            f"significant; withholding forever is as wrong as never withholding"
        ),
        on_iteration=_publish_dense,
    )
    repaired_srd = json.loads(repaired["StateReasonData"])
    repaired_window = repaired_srd["recentDatapoints"]
    assert repaired_window and min(float(v) for v in repaired_window) > _THRESHOLD, (
        f"the repaired ignore twin fired over recentDatapoints {repaired_window!r}; every value "
        f"published in this check is above the threshold {_THRESHOLD}, so a value at or below it "
        f"means the p50 was computed over something else"
    )

    # --- beat 4: the withholding is proven from the service's own timestamps ------------------- #
    ignore_fired_at = _first_alarm_timestamp(cw, ignore_name)
    assert ignore_fired_at > evaluate_fired_at, (
        f"the 'ignore' twin's first ALARM transition is stamped {ignore_fired_at.isoformat()} and "
        f"the 'evaluate' twin's {evaluate_fired_at.isoformat()}; the ignore twin must transition "
        f"STRICTLY LATER, because it was only permitted to once the sample count rose. Equal or "
        f"earlier timestamps mean both alarms fired on the sparse data and the enum was ignored"
    )


# ===== helpers =====
def _describe_all(cw, names):
    """Every metric alarm in *names*, via a paginated DescribeAlarms."""
    out = []
    for page in cw.get_paginator("describe_alarms").paginate(
        AlarmNames=list(names), AlarmTypes=["MetricAlarm"]
    ):
        out.extend(page.get("MetricAlarms", []))
    return out


def _describe(cw, alarm_name):
    for alarm in _describe_all(cw, [alarm_name]):
        if alarm["AlarmName"] == alarm_name:
            return alarm
    raise AssertionError(f"alarm {alarm_name!r} is not present in DescribeAlarms")


def _state_updates(cw, alarm_name):
    items = []
    for page in cw.get_paginator("describe_alarm_history").paginate(
        AlarmName=alarm_name, HistoryItemType="StateUpdate", ScanBy="TimestampAscending"
    ):
        items.extend(page.get("AlarmHistoryItems", []))
    return items


def _new_state(item) -> str:
    return json.loads(item["HistoryData"]).get("newState", {}).get("stateValue", "")


def _first_alarm_timestamp(cw, alarm_name):
    """The Timestamp of the OLDEST StateUpdate item whose newState is ALARM."""
    for item in _state_updates(cw, alarm_name):
        if _new_state(item) == "ALARM":
            return item["Timestamp"]
    raise AssertionError(
        f"alarm {alarm_name!r} has no StateUpdate history item recording an ALARM transition, so "
        f"the transition this check observed via DescribeAlarms was never recorded server-side"
    )


def _poll_until(probe, predicate, *, timeout_s, interval_s, description, on_iteration=None):
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
        if on_iteration is not None:
            on_iteration()
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
