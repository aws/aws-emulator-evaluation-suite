"""alarm-missing-data-and-m-of-n-period-window-slides-by-minute-and-never-evaluates-a-partial-period."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "alarm-missing-data-and-m-of-n-period-window-slides-by-minute-and-never-evaluates-a-partial-period"
GROUP = "evaluation"
SERVICES = ["cloudwatch"]

_PERIOD = 300
_HIGH = 100.0
_LOW = 1.0
# Any 5 consecutive minutes of the alternating series sum to 3*100+2*1=302 or 2*100+3*1=203.
_THRESHOLD = 250.0


def _value(minute: datetime) -> float:
    return _HIGH if int(minute.timestamp() // 60) % 2 == 0 else _LOW


# timing:real-time — metric: 190 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:happy-path", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "cap:c1",
      "timing:real-time")
def run(ctx) -> None:
    """A Period=300 alarm over a per-minute series evaluates complete 5-sample windows re-anchored
    every minute, while GetMetricStatistics buckets the same data on 300 s epoch boundaries.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
    """
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealPeriodSlide")
    metric = "PerMinute"
    # Sum and SampleCount are not idempotent under re-publishing, so each minute is published once.
    ledger: dict[datetime, float] = {}

    def _publish_new() -> None:
        now = datetime.now(timezone.utc)
        head = now.replace(second=0, microsecond=0)
        batch = []
        for i in range(12):
            minute = head - timedelta(minutes=i)
            if minute in ledger or now < minute + timedelta(seconds=5):
                continue
            ledger[minute] = _value(minute)
            batch.append({"MetricName": metric, "Timestamp": minute + timedelta(seconds=5),
                          "Value": ledger[minute], "Unit": "Count"})
        if batch:
            cw.put_metric_data(Namespace=namespace, MetricData=batch)

    _publish_new()

    alarm = ctx.unique_name("sim2real-period-slide-")
    cw.put_metric_alarm(
        AlarmName=alarm,
        Namespace=namespace,
        MetricName=metric,
        Statistic="Sum",
        Period=_PERIOD,
        EvaluationPeriods=1,
        DatapointsToAlarm=1,
        Threshold=_THRESHOLD,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="missing",
        ActionsEnabled=False,
        AlarmDescription="sim2real: how a 300 s Period buckets a 60 s series",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm]))

    # The alternating series makes every one-minute slide a transition, so each window lands in
    # history. Poll, publishing each new minute once, until 4 evaluated windows are recorded.
    deadline = time.monotonic() + 540.0
    while True:
        _publish_new()
        evaluated = [
            (item_ts, m) for item_ts, m in _moves(cw, alarm)
            if m["newState"].get("stateReasonData", {}).get("evaluatedDatapoints")
        ]
        if len(evaluated) >= 4:
            break
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"a Period=300 alarm over a flapping per-minute series recorded {len(evaluated)} "
                f"evaluated windows in 540s, expected at least 4"
            )
        time.sleep(5.0)

    starts = []
    for item_ts, move in evaluated:
        srd = move["newState"]["stateReasonData"]
        assert srd["period"] == _PERIOD and srd["statistic"] == "Sum", (
            f"the evaluation recorded period={srd.get('period')!r} "
            f"statistic={srd.get('statistic')!r}"
        )
        (point,) = srd["evaluatedDatapoints"]
        start = _ts(srd["startDate"])
        assert _ts(point["timestamp"]) == start, (
            f"the evaluated datapoint is stamped {point['timestamp']!r} but the window starts "
            f"{srd['startDate']!r}"
        )
        assert start.second == 0 and start.microsecond == 0, (
            f"the evaluated window starts at {start!r}, not on a minute boundary"
        )
        minutes = [start + timedelta(minutes=i) for i in range(5)]
        # Never a partial period: exactly the five one-minute samples of the window.
        assert point["sampleCount"] == 5.0, (
            f"the window starting {start!r} aggregated {point['sampleCount']!r} samples; a 300 s "
            f"Period over a 60 s series is exactly 5 -- fewer means a partial period was evaluated"
        )
        missing = [m for m in minutes if m not in ledger]
        assert not missing, (
            f"the window starting {start!r} covers minutes this check never published: {missing!r}"
        )
        want = sum(ledger[m] for m in minutes)
        assert point["value"] == want, (
            f"the window [{start!r}, +300 s) evaluated Sum {point['value']!r}; the five minutes this "
            f"check published there sum to {want!r}"
        )
        # The window closed before the evaluation that read it: the open minute is excluded.
        assert start + timedelta(seconds=_PERIOD) <= item_ts, (
            f"the evaluation at {item_ts!r} read a window ending {start + timedelta(seconds=_PERIOD)!r}"
            f", which had not closed yet"
        )
        want_state = "ALARM" if want > _THRESHOLD else "OK"
        assert move["newState"]["stateValue"] == want_state, (
            f"window Sum {want!r} vs threshold {_THRESHOLD!r} must be {want_state!r}, the evaluator "
            f"said {move['newState']['stateValue']!r}"
        )
        starts.append(start)

    deltas = [(b - a).total_seconds() for a, b in zip(starts, starts[1:])]
    assert all(d > 0 and d % 60 == 0 for d in deltas), (
        f"successive evaluated windows start at {starts!r} (deltas {deltas!r}); each must be a later "
        f"whole minute"
    )
    assert 60.0 in deltas, (
        f"successive evaluated windows start at {starts!r} (deltas {deltas!r}); a Period=300 alarm "
        f"re-anchors its window every minute, so consecutive evaluations 60 s apart must appear. "
        f"Deltas that are all multiples of 300 mean fixed buckets, which is not what AWS does"
    )
    aligned = [s for s in starts if int(s.timestamp()) % _PERIOD == 0]
    assert len(aligned) < len(starts), (
        f"every evaluated window {starts!r} starts on a 300 s epoch boundary; real CloudWatch alarm "
        f"windows are anchored to the minute, not to the Period"
    )

    # Contrast: the QUERY API buckets the same data on 300 s epoch boundaries.
    first = min(ledger)
    q_start = datetime.fromtimestamp((int(first.timestamp()) // _PERIOD + 1) * _PERIOD, timezone.utc)
    q_end = q_start + timedelta(seconds=2 * _PERIOD)
    buckets = cw.get_metric_statistics(
        Namespace=namespace, MetricName=metric, StartTime=q_start, EndTime=q_end,
        Period=_PERIOD, Statistics=["Sum", "SampleCount"],
    )["Datapoints"]
    assert buckets, f"GetMetricStatistics(Period=300) returned no buckets over {q_start!r}..{q_end!r}"
    for b in buckets:
        assert int(b["Timestamp"].timestamp()) % _PERIOD == 0, (
            f"GetMetricStatistics bucket stamped {b['Timestamp']!r} is not on a 300 s boundary"
        )
        mins = [b["Timestamp"] + timedelta(minutes=i) for i in range(5)]
        if all(m in ledger for m in mins):
            assert b["Sum"] == sum(ledger[m] for m in mins) and b["SampleCount"] == 5.0, (
                f"query bucket {b!r} does not match the ledger for {mins!r}"
            )


def _ts(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%f%z")


def _moves(cw, alarm_name):
    """(item timestamp, parsed HistoryData) for every StateUpdate, oldest first, paginated."""
    out = []
    for page in cw.get_paginator("describe_alarm_history").paginate(
        AlarmName=alarm_name, HistoryItemType="StateUpdate", ScanBy="TimestampAscending"
    ):
        out.extend((i["Timestamp"], json.loads(i["HistoryData"]))
                   for i in page.get("AlarmHistoryItems", []))
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
