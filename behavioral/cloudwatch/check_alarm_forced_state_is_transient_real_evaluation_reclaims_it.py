"""alarm-forced-state-is-transient-real-evaluation-reclaims-it."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "alarm-forced-state-is-transient-real-evaluation-reclaims-it"
GROUP = "evaluation"
SERVICES = ["cloudwatch"]

_THRESHOLD = 10.0
_CLEAR_VALUE = 1.0
_FORCED_REASON = "sim2real: forced"
_RECLAIM_BUDGET_S = 300.0


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:metrics", "dp:api", "plane:data",
      "timing:real-time")
def run(ctx) -> None:
    """SetAlarmState is a transient override: with no further call, the evaluator reclaims a forced
    ALARM to OK (citing this check's datapoint) or INSUFFICIENT_DATA (no data, 'missing'), while
    TreatMissingData='ignore' keeps it; the forced history item carries no stateReasonData.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_SetAlarmState.html
    """
    cw = ctx.client("cloudwatch")
    # Unique per run: CloudWatch has no API to delete a metric or namespace.
    namespace = ctx.unique_name("Sim2RealReclaimNs")
    metric = "ReclaimMetric"
    never_written = "NeverWrittenMetric"
    alarm_name = ctx.unique_name("sim2real-reclaim-")
    control_name = ctx.unique_name("sim2real-reclaim-control-")
    hold_name = ctx.unique_name("sim2real-reclaim-hold-")

    def _publish() -> None:
        # A clear (in-band) datapoint at the current minute boundary. Timestamped explicitly rather
        # than letting the server stamp it, so the point lands in a known evaluation period.
        cw.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": metric,
                    "Timestamp": _minute_floor(),
                    "Value": _CLEAR_VALUE,
                    "Unit": "Count",
                }
            ],
        )

    def _create(name: str, metric_name: str, treat_missing: str) -> None:
        cw.put_metric_alarm(
            AlarmName=name,
            Namespace=namespace,
            MetricName=metric_name,
            Statistic="Maximum",
            Period=60,
            EvaluationPeriods=1,
            DatapointsToAlarm=1,
            Threshold=_THRESHOLD,
            ComparisonOperator="GreaterThanThreshold",
            TreatMissingData=treat_missing,
            ActionsEnabled=False,
            AlarmDescription="sim2real depth: a forced alarm state is transient",
        )

    _publish()
    # 'missing' RETAINS state across an empty period, so the reclaim below cannot be a gap fill.
    _create(alarm_name, metric, "missing")
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))
    _create(control_name, never_written, "missing")
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[control_name]))
    # 'ignore' means "do not evaluate, keep the state you have", so this one must NOT be reclaimed.
    _create(hold_name, never_written, "ignore")
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[hold_name]))

    # --- 1. a REAL OK baseline, reached by the evaluator from real data ----------------------------
    baseline = _poll_until(
        lambda: _describe(cw, alarm_name),
        lambda a: a["StateValue"] == "OK",
        timeout_s=300.0,
        interval_s=15.0,
        description=f"alarm {alarm_name!r} reached OK from a published {_CLEAR_VALUE} datapoint",
        on_iteration=_publish,
    )
    assert baseline["StateReason"].startswith("Threshold Crossed"), (
        f"the OK baseline's StateReason is {baseline['StateReason']!r}; a real evaluated OK is "
        f"prefixed 'Threshold Crossed', so this baseline was not produced by an evaluation"
    )

    # --- 2. force ALARM. This is the ONLY set_alarm_state call for this alarm in this file. --------
    cw.set_alarm_state(AlarmName=alarm_name, StateValue="ALARM", StateReason=_FORCED_REASON)
    cw.set_alarm_state(AlarmName=control_name, StateValue="ALARM", StateReason=_FORCED_REASON)
    cw.set_alarm_state(AlarmName=hold_name, StateValue="ALARM", StateReason=_FORCED_REASON)
    # The evaluator may reclaim the override at its next evaluation, at any time after the call,
    # so the override is proven by its OK -> ALARM history item (step 5), not by a later read.

    # --- 3. publish in-band data and make NO further control-plane call to this alarm --------------
    reclaimed = _poll_until(
        lambda: _describe(cw, alarm_name),
        lambda a: a["StateValue"] == "OK",
        timeout_s=_RECLAIM_BUDGET_S,
        interval_s=15.0,
        description=(
            f"the forced ALARM on {alarm_name!r} was RECLAIMED to OK by CloudWatch's own evaluator "
            f"while {_CLEAR_VALUE} was published against a threshold of {_THRESHOLD}, with no "
            f"further set_alarm_state call (measured on real AWS at 30.2s)"
        ),
        interval_s_first=5.0,
        on_iteration=_publish,
    )

    assert reclaimed["StateReason"] != _FORCED_REASON, (
        f"the alarm returned to OK but its StateReason is still {reclaimed['StateReason']!r}; the "
        f"evaluator REWRITES the reason, so an implementation that re-derives the state and keeps "
        f"the client's string is diverging"
    )
    assert reclaimed["StateReason"].startswith("Threshold Crossed"), (
        f"the reclaiming StateReason is {reclaimed['StateReason']!r}; real CloudWatch prefixes an "
        f"evaluated transition with 'Threshold Crossed'"
    )
    assert "1 out of the last 1 datapoints" in reclaimed["StateReason"], (
        f"the reclaiming StateReason is {reclaimed['StateReason']!r} and does not name the "
        f"datapoint count the engine evaluated (EvaluationPeriods=1, DatapointsToAlarm=1)"
    )

    # --- 4. the reclaiming decision cites THIS check's published value -----------------------------
    updates = _poll_until(
        lambda: _state_updates(cw, alarm_name),
        lambda items: any(
            json.loads(i["HistoryData"]).get("oldState", {}).get("stateValue") == "ALARM"
            and json.loads(i["HistoryData"]).get("newState", {}).get("stateValue") == "OK"
            for i in items
        ),
        timeout_s=90.0,
        interval_s=5.0,
        description=f"a StateUpdate history item recording the ALARM->OK reclaim on {alarm_name!r}",
    )
    # _state_updates scans TimestampDescending; later evaluations may append transitions after the
    # reclaim, so the first three in time order are the baseline, the force and the reclaim.
    ordered = list(reversed(updates))[:3]
    hist = [json.loads(i["HistoryData"]) for i in ordered]
    reclaim_item = next(
        h
        for h in hist
        if h.get("oldState", {}).get("stateValue") == "ALARM"
        and h.get("newState", {}).get("stateValue") == "OK"
    )
    reason_data = reclaim_item["newState"]["stateReasonData"]
    assert _CLEAR_VALUE in reason_data["recentDatapoints"], (
        f"the reclaiming decision's recentDatapoints are "
        f"{reason_data['recentDatapoints']!r} and do not contain the published "
        f"{_CLEAR_VALUE!r} -- the OK was not derived from this check's data"
    )
    assert reason_data["threshold"] == _THRESHOLD, (
        f"the reclaiming decision recorded threshold {reason_data['threshold']!r}, expected "
        f"{_THRESHOLD!r} echoed from the alarm's configuration"
    )
    evaluated = reason_data["evaluatedDatapoints"]
    assert [d["value"] for d in evaluated] == [_CLEAR_VALUE], (
        f"the engine's evaluatedDatapoints are {evaluated!r}; a 1-of-1 window that reclaimed on "
        f"this check's data must contain exactly one datapoint valued {_CLEAR_VALUE!r}"
    )

    # --- 5. the FORCED transition has no evaluator decision record behind it ----------------------
    forced_entry, forced_item = next(
        (i, h)
        for i, h in zip(ordered, hist)
        if h.get("oldState", {}).get("stateValue") == "OK"
        and h.get("newState", {}).get("stateValue") == "ALARM"
    )
    assert forced_item["newState"]["stateReason"] == _FORCED_REASON, (
        f"the OK->ALARM history item's reason is "
        f"{forced_item['newState']['stateReason']!r}, expected the client's {_FORCED_REASON!r}"
    )
    assert "stateReasonData" not in forced_item["newState"], (
        f"the client-forced transition carries a stateReasonData "
        f"{forced_item['newState'].get('stateReasonData')!r}; real CloudWatch records NO decision "
        f"data for a SetAlarmState transition, because no evaluation produced it -- an emulator "
        f"that synthesises one is inventing an evaluation that never happened"
    )
    assert reclaimed["StateUpdatedTimestamp"] > forced_entry["Timestamp"], (
        f"StateUpdatedTimestamp did not advance across the reclaim: forced at "
        f"{forced_entry['Timestamp']!r}, reclaimed at {reclaimed['StateUpdatedTimestamp']!r}"
    )

    # --- 6. three transitions, and the middle one is the only client-caused one --------------------
    sequence = [
        (h["oldState"]["stateValue"], h["newState"]["stateValue"])
        for h in hist
    ]
    assert sequence == [
        ("INSUFFICIENT_DATA", "OK"),
        ("OK", "ALARM"),
        ("ALARM", "OK"),
    ], (
        f"the alarm's first StateUpdate history items are {sequence!r}; expected three transitions -- "
        f"the evaluated baseline, the client's force, and the evaluator taking it back"
    )

    # --- 7. the destination is COMPUTED from the data, not decayed to a constant -------------------
    # Same forced ALARM, same instant, same threshold; this sibling's metric was never written and
    # its TreatMissingData is 'missing', so the evaluator's verdict for it is INSUFFICIENT_DATA --
    # a third value, which an implementation that merely expires forced states cannot produce.
    control = _poll_until(
        lambda: _describe(cw, control_name),
        lambda a: a["StateValue"] != "ALARM",
        timeout_s=300.0,
        interval_s=10.0,
        description=(
            f"the forced ALARM on {control_name!r} -- whose metric {never_written!r} is never "
            f"written -- was reclaimed by the evaluator (measured on real AWS at 70.8s)"
        ),
    )
    assert control["StateValue"] == "INSUFFICIENT_DATA", (
        f"the never-written control was reclaimed to {control['StateValue']!r}; with "
        f"TreatMissingData='missing' and an empty window the evaluator computes INSUFFICIENT_DATA, "
        f"not the OK it computed for the alarm that DID have a datapoint. An emulator that decays "
        f"every forced state to one constant is caught by the pair"
    )
    assert control["StateReason"] == "Insufficient Data: 1 datapoint was unknown.", (
        f"the control's reclaimed StateReason is {control['StateReason']!r}; real CloudWatch writes "
        f"'Insufficient Data: 1 datapoint was unknown.' -- it names the empty window, and it is not "
        f"the client's {_FORCED_REASON!r}"
    )

    # --- 8. negative space: TreatMissingData='ignore' means the evaluator does NOT reclaim ---------
    # 'ignore' is "do not evaluate, keep the state you have". Its persistence is what proves the two
    # reclaims above were caused by evaluation rather than by forced states expiring on a timer.
    held = _describe(cw, hold_name)
    assert held["StateValue"] == "ALARM", (
        f"the TreatMissingData='ignore' sibling reports {held['StateValue']!r} with reason "
        f"{held['StateReason']!r}; 'ignore' retains the prior state, so it must still hold the "
        f"forced ALARM. If forced states expired on their own, the reclaims above would prove "
        f"nothing about evaluation"
    )
    assert held["StateReason"] == _FORCED_REASON, (
        f"the 'ignore' sibling's StateReason is {held['StateReason']!r}, expected the unchanged "
        f"{_FORCED_REASON!r} -- nothing re-explained a state that never transitioned"
    )
    assert _state_updates(cw, hold_name) and all(
        json.loads(i["HistoryData"])["newState"]["stateValue"] == "ALARM"
        for i in _state_updates(cw, hold_name)
    ), (
        f"the 'ignore' sibling recorded a StateUpdate other than the forced ALARM: "
        f"{[i['HistoryData'] for i in _state_updates(cw, hold_name)]!r}. An implementation that "
        f"re-evaluates and re-writes the same state emits self-transitions; real CloudWatch does not"
    )

    # --- 9. cleanup is verified, not assumed ------------------------------------------------------
    everything = [alarm_name, control_name, hold_name]
    cw.delete_alarms(AlarmNames=everything)
    assert _describe_all(cw, everything) == [], (
        f"DeleteAlarms left {_describe_all(cw, everything)!r} behind"
    )


def _minute_floor():
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).replace(second=0, microsecond=0)


def _describe_all(cw, names):
    """Every metric alarm in *names*, via a paginated DescribeAlarms.

    Paginated because other alarms in the account can push a result off page one. DescribeAlarms
    defaults AlarmTypes to ['MetricAlarm'] only, which is what these alarms are.
    """
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
        AlarmName=alarm_name, HistoryItemType="StateUpdate", ScanBy="TimestampDescending"
    ):
        items.extend(page.get("AlarmHistoryItems", []))
    return items


def _poll_until(
    probe,
    predicate,
    *,
    timeout_s,
    interval_s,
    description,
    on_iteration=None,
    interval_s_first=None,
):
    """Poll probe() until predicate(result); FAIL on exhaustion, never skip."""
    deadline = time.monotonic() + timeout_s
    interval = interval_s_first or interval_s
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
        time.sleep(interval)
        interval = interval_s


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
