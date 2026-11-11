"""alarm-unit-filter-withholds-evaluation-until-the-unit-matches."""
from __future__ import annotations

# On real AWS:
#   - an alarm whose Unit does not match any published datapoint's unit sees an EMPTY dataset and
#     stays in INSUFFICIENT_DATA under TreatMissingData='missing';
#   - that alarm keeps its create-time StateReason 'Unchecked: Initial alarm creation': 'missing'
#     is a no-op on absence, so absence is proven by a freeze (StateValue and StateReason constant
#     across reads spanning 3x the control's time-to-fire) plus zero ALARM history;
#   - publishing the SAME metric and dimensions under the alarm's unit creates a unit-scoped series
#     the alarm then evaluates: the unit filter applies at read time, not at create time;
#   - an alarm created with Unit= reads that Unit back from DescribeAlarms.

import json
import time
from datetime import datetime, timezone

from behavioral_harness import tags

CHECK = "alarm-unit-filter-withholds-evaluation-until-the-unit-matches"
GROUP = "evaluation"
SERVICES = ["cloudwatch"]

_THRESHOLD = 10.0
_VALUE = 500.0
_PUBLISHED_UNIT = "Milliseconds"
_ALARM_UNIT = "Bytes"


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:negative-delivery", "cap:c4", "concern:data-plane", "concern:metrics", "dp:api",
      "plane:data", "timing:real-time")
def run(ctx) -> None:
    """An alarm's Unit is part of the metric identity it EVALUATES: a Unit='Bytes' alarm over a
    Milliseconds series stays frozen with no ALARM history while its no-Unit twin alarms, then fires
    strictly after the twin once the same value is published as Bytes."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealAlarmUnitNs")
    metric = "UnitScopedLatency"
    matching_name = ctx.unique_name("sim2real-alarmunit-nofilter-")
    mismatched_name = ctx.unique_name("sim2real-alarmunit-bytes-")

    published_unit = [_PUBLISHED_UNIT]

    def _publish() -> None:
        cw.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": metric,
                    "Timestamp": datetime.now(timezone.utc).replace(second=0, microsecond=0),
                    "Value": _VALUE,
                    "Unit": published_unit[0],
                }
            ],
        )

    def _create(name: str, unit: str | None) -> None:
        kwargs = dict(
            AlarmName=name,
            Namespace=namespace,
            MetricName=metric,
            Statistic="Maximum",
            Period=60,
            EvaluationPeriods=1,
            DatapointsToAlarm=1,
            Threshold=_THRESHOLD,
            ComparisonOperator="GreaterThanThreshold",
            # 'missing' keeps a no-data alarm in INSUFFICIENT_DATA instead of letting a
            # missing-data policy decide the state -- the subject here is the unit filter, and
            # 'breaching' or 'notBreaching' would answer beat 2 for the wrong reason.
            TreatMissingData="missing",
            ActionsEnabled=False,
            AlarmDescription=f"sim2real depth: alarm unit filter, Unit={unit!r}",
            Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        )
        if unit is not None:
            kwargs["Unit"] = unit
        cw.put_metric_alarm(**kwargs)

    # Seed one period before the alarms exist so their first evaluation has something to resolve.
    _publish()

    _create(matching_name, None)
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[matching_name]))
    _create(mismatched_name, _ALARM_UNIT)
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[mismatched_name]))

    matching = _describe(cw, matching_name)
    mismatched = _describe(cw, mismatched_name)
    assert "Unit" not in matching, (
        f"the control alarm reports Unit={matching.get('Unit')!r}; it was created without one, and "
        f"an invented unit would make it a second unit-filtered alarm rather than the unfiltered "
        f"control this check needs"
    )
    assert mismatched.get("Unit") == _ALARM_UNIT, (
        f"the filtered alarm read back Unit={mismatched.get('Unit')!r}, expected {_ALARM_UNIT!r} -- "
        f"a target that dropped the field on the way in would make beat 2 vacuous"
    )
    differing = {
        key
        for key in (
            "Namespace", "MetricName", "Statistic", "Period", "EvaluationPeriods",
            "DatapointsToAlarm", "Threshold", "ComparisonOperator", "TreatMissingData",
        )
        if matching.get(key) != mismatched.get(key)
    }
    assert not differing, (
        f"the two alarms differ in {sorted(differing)!r} as well as in Unit, so any divergence in "
        f"state below cannot be attributed to the unit filter"
    )
    # The control's data already exists, so its first evaluation may land before this read.
    for name, alarm, allowed in (
        (matching_name, matching, ("INSUFFICIENT_DATA", "ALARM")),
        (mismatched_name, mismatched, ("INSUFFICIENT_DATA",)),
    ):
        assert alarm["StateValue"] in allowed, (
            f"alarm {name!r} started in {alarm['StateValue']!r}, expected one of {allowed!r}"
        )

    # --- beat 1: the unfiltered control fires on the Milliseconds series ---------------------- #
    beat1_t0 = time.monotonic()
    fired = _poll_until(
        lambda: _describe(cw, matching_name),
        lambda a: a["StateValue"] == "ALARM",
        timeout_s=300.0,
        interval_s=15.0,
        description=(
            f"the no-Unit control alarm {matching_name!r} fired on a {_PUBLISHED_UNIT} series of "
            f"{_VALUE} against threshold {_THRESHOLD}"
        ),
        on_iteration=_publish,
    )
    beat1_elapsed_s = time.monotonic() - beat1_t0
    window = json.loads(fired["StateReasonData"])["recentDatapoints"]
    assert len(window) == 1 and abs(float(window[0]) - _VALUE) < 1e-6, (
        f"the control fired over recentDatapoints {window!r}, expected exactly [{_VALUE!r}] -- the "
        f"only value this check has published"
    )
    control_fired_at = _first_alarm_timestamp(cw, matching_name)

    # --- beat 2: hold the Bytes-filtered twin under observation across a calibrated window ----- #
    # Under TreatMissingData='missing' an alarm that never sees a datapoint under its own unit keeps
    # its CREATE-time state, so the observables are a FREEZE of StateValue and StateReason across a
    # window sized off the control's time-to-fire, and no ALARM entry in the twin's history.
    baseline_reason = mismatched.get("StateReason")
    hold_s = max(3.0 * beat1_elapsed_s, 60.0)
    interval_s = 30.0
    n_reads = max(4, int(hold_s // interval_s) + 1)
    readings = []
    for i in range(n_reads):
        readings.append(_describe(cw, mismatched_name))
        if i < n_reads - 1:
            time.sleep(interval_s)
    observed_states = [r["StateValue"] for r in readings]
    assert set(observed_states) == {"INSUFFICIENT_DATA"}, (
        f"the Unit={_ALARM_UNIT!r} alarm's state moved during a {hold_s:.0f}s hold calibrated at "
        f"3x the control's own {beat1_elapsed_s:.0f}s time-to-fire ({n_reads} independent reads): "
        f"observed {observed_states!r}. It must stay INSUFFICIENT_DATA until fed a datapoint under "
        f"its own unit -- every datapoint this check has published so far carries "
        f"Unit={_PUBLISHED_UNIT!r}"
    )
    observed_reasons = {r.get("StateReason") for r in readings}
    assert observed_reasons == {baseline_reason}, (
        f"the Unit={_ALARM_UNIT!r} alarm's StateReason moved from its own baseline "
        f"{baseline_reason!r} to {sorted(r for r in observed_reasons if r != baseline_reason)!r} "
        f"during the hold; real AWS never rewrites this text under TreatMissingData='missing' "
        f"while no datapoint has ever matched the alarm's unit, so any change means the target is "
        f"resolving a series this alarm should not be able to see"
    )
    withheld = readings[-1]
    early = [i for i in _state_updates(cw, mismatched_name) if _new_state(i) == "ALARM"]
    assert early == [], (
        f"the Unit={_ALARM_UNIT!r} alarm's history already records {len(early)} ALARM transitions "
        f"{early!r}; the DescribeAlarms snapshots above could in principle have been read between a "
        f"fire and a recovery, the history cannot"
    )

    # --- beat 3: restore -- publish the SAME value under the alarm's unit --------------------- #
    published_unit[0] = _ALARM_UNIT
    _publish()
    repaired = _poll_until(
        lambda: _describe(cw, mismatched_name),
        lambda a: a["StateValue"] == "ALARM",
        timeout_s=420.0,
        interval_s=15.0,
        description=(
            f"the Unit={_ALARM_UNIT!r} alarm fired once a datapoint was published under that unit; "
            f"an alarm that withholds forever is as wrong as one that ignores the filter, and this "
            f"beat is what proves the unit filter is applied at read time rather than frozen at "
            f"create time"
        ),
        on_iteration=_publish,
    )
    repaired_window = json.loads(repaired["StateReasonData"])["recentDatapoints"]
    assert repaired_window and all(abs(float(v) - _VALUE) < 1e-6 for v in repaired_window), (
        f"the repaired alarm fired over recentDatapoints {repaired_window!r}, expected every value "
        f"to be {_VALUE!r}"
    )
    assert repaired["Unit"] == _ALARM_UNIT, (
        f"after the transition the alarm reports Unit={repaired.get('Unit')!r}, expected it to "
        f"still be {_ALARM_UNIT!r} -- the filter must not be rewritten by what it matched"
    )

    # --- beat 4: the withholding is proven from the service's own timestamps ------------------ #
    repaired_at = _first_alarm_timestamp(cw, mismatched_name)
    assert repaired_at > control_fired_at, (
        f"the Unit={_ALARM_UNIT!r} alarm's first ALARM transition is stamped "
        f"{repaired_at.isoformat()} and the unfiltered control's {control_fired_at.isoformat()}; "
        f"the filtered alarm must transition STRICTLY LATER, because it had no matching series "
        f"until beat 3. Equal or earlier means both alarms evaluated the {_PUBLISHED_UNIT!r} "
        f"series and the unit filter was never applied"
    )


# ===== helpers =====
def _describe_all(cw, names):
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
    for item in _state_updates(cw, alarm_name):
        if _new_state(item) == "ALARM":
            return item["Timestamp"]
    raise AssertionError(
        f"alarm {alarm_name!r} has no StateUpdate history item recording an ALARM transition, so "
        f"the transition observed via DescribeAlarms was never recorded server-side"
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
