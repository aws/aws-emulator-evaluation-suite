"""high-resolution-alarm-evaluates-ten-second-periods-and-rejects-invalid-period."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "high-resolution-alarm-evaluates-ten-second-periods-and-rejects-invalid-period"
GROUP = "evaluation"
SERVICES = ["cloudwatch"]

_THRESHOLD = 10.0
_BREACH = 99.0
_HIRES_PERIOD = 10
_HIRES_N = 3
# The legal sub-minute periods are exactly 10, 20 and 30.
_BAD_PERIOD = 45
_BAD_PERIOD_MESSAGE = "Period must be 10, 20, 30 or a multiple of 60"


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:rejection", "cap:c4", "concern:metrics", "concern:negative-classes",
      "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A Period=10 alarm transitions sooner than a 60-second tick allows and evaluates datapoints
    10 s apart; Period=45 is rejected with ValidationError and no alarm is created.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
    """
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealHiResNs")
    metric = "HiResMetric"
    hires = ctx.unique_name("sim2real-hires-")
    standard = ctx.unique_name("sim2real-standard-")
    thirty = ctx.unique_name("sim2real-thirty-")
    bad = ctx.unique_name("sim2real-badperiod-")

    def _create(name: str, period: int, evaluation_periods: int) -> None:
        cw.put_metric_alarm(
            AlarmName=name,
            Namespace=namespace,
            MetricName=metric,
            Statistic="Maximum",
            Period=period,
            EvaluationPeriods=evaluation_periods,
            DatapointsToAlarm=evaluation_periods,
            Threshold=_THRESHOLD,
            ComparisonOperator="GreaterThanThreshold",
            TreatMissingData="missing",
            ActionsEnabled=False,
            AlarmDescription="sim2real depth: the evaluator's tick is the alarm's period",
        )

    def _publish() -> None:
        # Ten per-second datapoints span at least two 10-second buckets; StorageResolution=1 is
        # what makes sub-minute retention legal at all.
        now = datetime.now(timezone.utc).replace(microsecond=0)
        cw.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": metric,
                    "Timestamp": now - timedelta(seconds=s),
                    "Value": _BREACH,
                    "Unit": "Count",
                    "StorageResolution": 1,
                }
                for s in range(10)
            ],
        )

    # Both alarms exist BEFORE any datapoint does, so their first state is a real one.
    _create(hires, _HIRES_PERIOD, _HIRES_N)
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[hires]))
    _create(standard, 60, 1)
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[standard]))
    _create(thirty, 30, 1)
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[thirty]))

    described = {a["AlarmName"]: a for a in _describe_all(cw, [hires, standard, thirty])}
    assert set(described) == {hires, standard, thirty}, (
        f"DescribeAlarms returned {sorted(described)!r}; all three alarms must exist"
    )
    assert described[hires]["Period"] == _HIRES_PERIOD, (
        f"the high-resolution alarm reads back Period={described[hires]['Period']!r}; an emulator "
        f"that silently normalises a sub-minute period to 60 is caught here, before any evaluation"
    )
    assert described[thirty]["Period"] == 30, (
        f"the Period=30 control reads back {described[thirty]['Period']!r}"
    )
    assert (
        described[hires]["EvaluationPeriods"],
        described[hires]["DatapointsToAlarm"],
    ) == (_HIRES_N, _HIRES_N), (
        f"the high-resolution alarm's window did not round-trip: "
        f"{described[hires]['EvaluationPeriods']!r}/{described[hires]['DatapointsToAlarm']!r}, "
        f"expected {_HIRES_N}/{_HIRES_N}"
    )
    for name in (hires, standard, thirty):
        assert described[name]["StateValue"] == "INSUFFICIENT_DATA", (
            f"alarm {name!r} was created in {described[name]['StateValue']!r} on a metric that has "
            f"never been written; INSUFFICIENT_DATA is a real first state and requires "
            f"distinguishing 'no data in the window' from 'data below threshold'"
        )

    code, message = _error(lambda: _create(bad, _BAD_PERIOD, 1))
    assert code == "ValidationError", (
        f"PutMetricAlarm with Period={_BAD_PERIOD} raised {code!r}; real AWS raises exactly "
        f"'ValidationError'. Accepting it means the emulator has no period lattice at all"
    )
    assert message == _BAD_PERIOD_MESSAGE, (
        f"the rejection message is {message!r}, not {_BAD_PERIOD_MESSAGE!r}; the "
        f"message is what tells a caller which periods ARE legal"
    )
    assert _describe_all(cw, [bad]) == [], (
        f"the refused Period={_BAD_PERIOD} alarm exists anyway: "
        f"{_describe_all(cw, [bad])!r} -- a rejection that still creates the resource is worse "
        f"than an acceptance"
    )

    _publish()
    first_publish = time.monotonic()
    fired_at: dict[str, float] = {}
    left = ctx.time_left()
    wait_s = max(1.0, min(300.0, (300.0 if left is None else left) - 20.0))
    deadline = first_publish + wait_s
    while len(fired_at) < 2:
        states = {a["AlarmName"]: a["StateValue"] for a in _describe_all(cw, [hires, standard])}
        for name in (hires, standard):
            if states.get(name) == "ALARM" and name not in fired_at:
                fired_at[name] = time.monotonic() - first_publish
        if len(fired_at) == 2:
            break
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"only {sorted(fired_at)!r} reached ALARM within {wait_s:.0f}s while {_BREACH} was "
                f"published per second against a threshold of {_THRESHOLD}; last states "
                f"{states!r}. The evaluator did not run, which is a FAIL and deliberately not a "
                f"skip"
            )
        _publish()
        time.sleep(2.0)

    # A 60-second-tick evaluator needs 3 x 60 s = 180 s for a 3-datapoint window.
    assert fired_at[hires] < 150.0, (
        f"the Period={_HIRES_PERIOD} alarm took {fired_at[hires]:.1f}s to satisfy a "
        f"{_HIRES_N}-datapoint window; a 60-second-minimum evaluator needs at least "
        f"{_HIRES_N * 60}s, so anything under 150s is only reachable with real sub-minute "
        f"evaluation (measured on real AWS: 40.3s)"
    )

    hires_srd = _alarm_decision(ctx, cw, hires)
    assert hires_srd["period"] == _HIRES_PERIOD, (
        f"the high-resolution alarm's decision record reports period {hires_srd['period']!r}; the "
        f"engine must state the cadence it evaluated at"
    )
    assert len(hires_srd["recentDatapoints"]) == _HIRES_N, (
        f"the engine compared {hires_srd['recentDatapoints']!r}; a {_HIRES_N}-period window means "
        f"{_HIRES_N} 10-second buckets, not one minute bucket"
    )
    assert set(hires_srd["recentDatapoints"]) == {_BREACH}, (
        f"the engine compared {hires_srd['recentDatapoints']!r}, expected every bucket's Maximum to "
        f"be the published {_BREACH!r}"
    )
    # queryDate is the evaluation instant, not the window end, so spacing is asserted instead.
    stamps = sorted(_parse_stamp(d["timestamp"]) for d in hires_srd["evaluatedDatapoints"])
    assert len(stamps) == _HIRES_N, (
        f"the engine counted {len(stamps)} datapoints ({stamps!r}), expected {_HIRES_N}"
    )
    gaps = [
        (stamps[i + 1] - stamps[i]).total_seconds() for i in range(len(stamps) - 1)
    ]
    assert gaps == [float(_HIRES_PERIOD)] * (_HIRES_N - 1), (
        f"the counted datapoints are spaced {gaps!r} seconds apart; a Period=10 alarm evaluates "
        f"consecutive 10-second buckets, and a store that only buckets by minute has nowhere to put "
        f"two datapoints inside one minute. This is the direct proof of sub-minute evaluation"
    )

    standard_srd = _alarm_decision(ctx, cw, standard)
    assert standard_srd["period"] == 60, (
        f"the control's decision record reports period {standard_srd['period']!r}, expected 60 -- "
        f"the two alarms must differ in exactly the asserted way"
    )
    assert len(standard_srd["evaluatedDatapoints"]) == 1, (
        f"the 1-of-1 control counted {standard_srd['evaluatedDatapoints']!r}, expected one "
        f"minute-wide datapoint"
    )

    cw.delete_alarms(AlarmNames=[hires, standard, thirty])
    assert _describe_all(cw, [hires, standard, thirty]) == [], (
        f"DeleteAlarms left {_describe_all(cw, [hires, standard, thirty])!r} behind"
    )


def _error(fn):
    """The error code and message of a call that must fail; an unexpected success raises."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - the code is asserted by the caller
        response = getattr(exc, "response", None)
        if not isinstance(response, dict):
            raise AssertionError(
                f"expected a modelled AWS error, got {type(exc).__name__}: {exc}"
            ) from exc
        err = response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError("the call succeeded; real AWS rejects it, so there is no error to compare")


def _parse_stamp(text: str) -> datetime:
    """Parse a stateReasonData timestamp such as 'YYYY-MM-DDTHH:MM:SS.000+0000'.

    The '+0000' offset has no colon, which datetime.fromisoformat rejects before Python 3.11.
    """
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    elif len(text) >= 5 and text[-5] in "+-" and ":" not in text[-5:]:
        text = text[:-2] + ":" + text[-2:]
    return datetime.fromisoformat(text)


def _describe_all(cw, names):
    """Every metric alarm in *names*, via a paginated DescribeAlarms."""
    out = []
    for page in cw.get_paginator("describe_alarms").paginate(
        AlarmNames=list(names), AlarmTypes=["MetricAlarm"]
    ):
        out.extend(page.get("MetricAlarms", []))
    return out


def _alarm_decision(ctx, cw, alarm_name):
    """The `stateReasonData` of the ALARM transition recorded in the alarm's own history."""
    def _items():
        items = []
        for page in cw.get_paginator("describe_alarm_history").paginate(
            AlarmName=alarm_name, HistoryItemType="StateUpdate", ScanBy="TimestampDescending"
        ):
            items.extend(page.get("AlarmHistoryItems", []))
        return [json.loads(i["HistoryData"]) for i in items]

    left = ctx.time_left()
    wait_s = max(1.0, min(90.0, (90.0 if left is None else left) - 5.0))
    deadline = time.monotonic() + wait_s
    while True:
        alarms = [h for h in _items() if h.get("newState", {}).get("stateValue") == "ALARM"]
        if alarms:
            return alarms[0]["newState"]["stateReasonData"]
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"no StateUpdate history item recording an ALARM transition for {alarm_name!r} "
                f"appeared within {wait_s:.0f}s; the alarm read ALARM but wrote no decision record"
            )
        time.sleep(2.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
