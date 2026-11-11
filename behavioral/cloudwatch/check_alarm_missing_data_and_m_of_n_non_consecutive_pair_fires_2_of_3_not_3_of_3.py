"""alarm-missing-data-and-m-of-n-non-consecutive-pair-fires-2-of-3-not-3-of-3."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "alarm-missing-data-and-m-of-n-non-consecutive-pair-fires-2-of-3-not-3-of-3"
GROUP = "evaluation"
SERVICES = ["cloudwatch"]

_THRESHOLD = 10.0
_BREACH = 99.0
_CLEAR = 1.0


def _alternating(minute: datetime) -> float:
    """Breach on even epoch-minutes: every 3-period window is [B,C,B] or [C,B,C]."""
    return _BREACH if int(minute.timestamp() // 60) % 2 == 0 else _CLEAR


def _one_in_three(minute: datetime) -> float:
    """Breach on every third epoch-minute: every 3-period window holds exactly ONE breach."""
    return _BREACH if int(minute.timestamp() // 60) % 3 == 0 else _CLEAR


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:happy-path", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "cap:c1", "timing:real-time")
def run(ctx) -> None:
    """With EvaluationPeriods=3, an alternating 99/1 series fires the DatapointsToAlarm=2 alarm on two
    non-adjacent breaching periods ("Threshold Crossed: 2 out of the last 3 datapoints [..."), while
    the same data never fires a 3-of-3 alarm and one breach per window never fires a 2-of-3 alarm."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealMofNGap")
    series = {"Alternating": _alternating, "OneInThree": _one_in_three}

    def _publish() -> None:
        head = datetime.now(timezone.utc).replace(second=0, microsecond=0)
        for metric, pattern in series.items():
            # Maximum over a repeated identical value is idempotent, so re-publishing the last 12
            # minutes each pass keeps the series gap-free without changing any period's statistic.
            cw.put_metric_data(
                Namespace=namespace,
                MetricData=[
                    {"MetricName": metric, "Timestamp": head - timedelta(minutes=i),
                     "Value": pattern(head - timedelta(minutes=i)), "Unit": "Count"}
                    for i in range(12)
                ],
            )

    _publish()

    def _create(prefix: str, metric: str, dta: int) -> str:
        name = ctx.unique_name(prefix)
        cw.put_metric_alarm(
            AlarmName=name,
            Namespace=namespace,
            MetricName=metric,
            Statistic="Maximum",
            Period=60,
            EvaluationPeriods=3,
            DatapointsToAlarm=dta,
            Threshold=_THRESHOLD,
            ComparisonOperator="GreaterThanThreshold",
            TreatMissingData="notBreaching",
            ActionsEnabled=False,
            AlarmDescription=f"sim2real: {dta}-of-3 over {metric}",
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
        ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[name]))
        return name

    alt_2 = _create("sim2real-mofn-alt2of3-", "Alternating", 2)
    alt_3 = _create("sim2real-mofn-alt3of3-", "Alternating", 3)
    one_2 = _create("sim2real-mofn-one2of3-", "OneInThree", 2)

    for name, dta in ((alt_2, 2), (alt_3, 3), (one_2, 2)):
        a = _describe(cw, name)
        assert (a["EvaluationPeriods"], a["DatapointsToAlarm"]) == (3, dta), (
            f"{name} stored EvaluationPeriods={a['EvaluationPeriods']!r} "
            f"DatapointsToAlarm={a['DatapointsToAlarm']!r}, expected (3, {dta})"
        )

    # --- positive: the non-consecutive pair fires the 2-of-3 alarm, at least twice --------------
    deadline = time.monotonic() + 540.0
    while True:
        _publish()
        fires = [m for m in _moves(cw, alt_2) if m["newState"]["stateValue"] == "ALARM"]
        if len(fires) >= 2:
            break
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"the 2-of-3 alarm over a [99,1,99] series fired {len(fires)} time(s) in 540s, "
                f"expected at least 2; its state is {_describe(cw, alt_2)['StateValue']!r}"
            )
        time.sleep(15.0)

    for fire in fires:
        srd = fire["newState"]["stateReasonData"]
        window = srd["recentDatapoints"]
        assert window == [_BREACH, _CLEAR, _BREACH], (
            f"the 2-of-3 alarm fired on window {window!r}; the only 3-window of this series with two "
            f"breaches is [99, 1, 99], with the clear period BETWEEN them"
        )
        counted = srd["evaluatedDatapoints"]
        assert len(counted) == 2 and {d["value"] for d in counted} == {_BREACH}, (
            f"the ALARM verdict counted {counted!r}; expected exactly the two {_BREACH!r} datapoints"
        )
        stamps = sorted(_ts(d["timestamp"]) for d in counted)
        assert (stamps[1] - stamps[0]).total_seconds() == 120.0, (
            f"the two counted breaches are at {stamps!r}; they must be two periods apart -- NOT "
            f"consecutive -- which is the claim"
        )
        assert srd["threshold"] == _THRESHOLD and srd["period"] == 60, (
            f"the ALARM decision recorded threshold={srd.get('threshold')!r} "
            f"period={srd.get('period')!r}"
        )
        reason = fire["newState"]["stateReason"]
        assert reason.startswith("Threshold Crossed: 2 out of the last 3 datapoints [") and (
            reason.endswith("were greater than the threshold (10.0) (minimum 2 datapoints for "
                            "OK -> ALARM transition).")
        ), f"the ALARM StateReason is {reason!r}"

    # --- negative 1: the SAME data, DatapointsToAlarm=3, never fires -----------------------------
    alt3_moves = _moves(cw, alt_3)
    assert alt3_moves, "the 3-of-3 alarm never evaluated at all (no StateUpdate history)"
    assert [m for m in alt3_moves if m["newState"]["stateValue"] == "ALARM"] == [], (
        f"the 3-of-3 alarm fired over the same [99,1,99] data the 2-of-3 alarm fired on: "
        f"{[m['newState']['stateReason'] for m in alt3_moves]!r}"
    )
    alt3_now = _describe(cw, alt_3)
    assert alt3_now["StateValue"] == "OK", (
        f"the 3-of-3 alarm is {alt3_now['StateValue']!r} ({alt3_now['StateReason']!r}); two "
        f"breaches in three periods can never satisfy 3-of-3, so its evaluated state is OK"
    )
    assert "(minimum 1 datapoint for ALARM -> OK transition)" in alt3_now["StateReason"], (
        f"the 3-of-3 OK reason {alt3_now['StateReason']!r} must name its OK minimum, "
        f"EvaluationPeriods-DatapointsToAlarm+1 = 1"
    )

    # --- negative 2: one breach per window, DatapointsToAlarm=2, never fires ---------------------
    one_moves = _moves(cw, one_2)
    assert one_moves, "the one-in-three 2-of-3 alarm never evaluated at all (no StateUpdate history)"
    assert [m for m in one_moves if m["newState"]["stateValue"] == "ALARM"] == [], (
        f"a 2-of-3 alarm fired over a series with only ONE breach per 3-period window: "
        f"{[m['newState']['stateReason'] for m in one_moves]!r}"
    )
    one_now = _describe(cw, one_2)
    assert one_now["StateValue"] == "OK", (
        f"the one-in-three 2-of-3 alarm is {one_now['StateValue']!r} ({one_now['StateReason']!r})"
    )
    one_window = json.loads(one_now["StateReasonData"])["recentDatapoints"]
    assert len(one_window) == 3 and [v for v in one_window if v > _THRESHOLD] == [_BREACH], (
        f"the one-in-three alarm's evaluated window is {one_window!r}; it must hold exactly one "
        f"breach, which is the M-1 condition that must not fire"
    )

    # --- the data really is what the verdicts say: read the series back ---------------------------
    end = datetime.now(timezone.utc).replace(second=0, microsecond=0) - timedelta(minutes=1)
    start = end - timedelta(minutes=6)
    for metric, pattern in series.items():
        points = cw.get_metric_statistics(
            Namespace=namespace, MetricName=metric, StartTime=start, EndTime=end,
            Period=60, Statistics=["Maximum"],
        )["Datapoints"]
        got = {p["Timestamp"]: p["Maximum"] for p in points}
        want = {start + timedelta(minutes=i): pattern(start + timedelta(minutes=i)) for i in range(6)}
        assert got == want, f"{metric} reads back as {sorted(got.items())!r}, expected {sorted(want.items())!r}"


def _ts(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%f%z")


def _describe(cw, alarm_name):
    for page in cw.get_paginator("describe_alarms").paginate(
        AlarmNames=[alarm_name], AlarmTypes=["MetricAlarm"]
    ):
        for alarm in page.get("MetricAlarms", []):
            if alarm["AlarmName"] == alarm_name:
                return alarm
    raise AssertionError(f"alarm {alarm_name!r} is not present in DescribeAlarms")


def _moves(cw, alarm_name):
    """Every StateUpdate's parsed HistoryData, oldest first, paginated."""
    out = []
    for page in cw.get_paginator("describe_alarm_history").paginate(
        AlarmName=alarm_name, HistoryItemType="StateUpdate", ScanBy="TimestampAscending"
    ):
        out.extend(json.loads(i["HistoryData"]) for i in page.get("AlarmHistoryItems", []))
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
