"""alarm-unit-and-percentile-traps-standard-resolution-accepts-sub-minute-period-but-buckets-by-minute."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = (
    "alarm-unit-and-percentile-traps-standard-resolution-accepts-sub-minute-period-but-buckets-by-minute"
)
GROUP = "evaluation"
SERVICES = ["cloudwatch"]

_THRESHOLD = 10.0
_VALUE = 99.0


# timing:real-time — metric: 10 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:metrics", "dp:api",
      "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Period=10 and 30 alarms on a standard-resolution metric are accepted and fire, but evaluate
    and query whole-minute buckets; a high-resolution Period=10 alarm uses true 10 s buckets.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
    """
    cw = ctx.client("cloudwatch")
    # A custom namespace cannot be deleted (no DeleteMetric API); it ages out.
    namespace = ctx.unique_name("Sim2RealResolutionNs")

    def _publish() -> None:
        now = datetime.now(timezone.utc)
        # The previous minute is already closed, so a whole-minute bucket is gradable at once.
        data = [{"MetricName": "StandardRes", "Timestamp": now - timedelta(seconds=back),
                 "Value": _VALUE} for back in (0, 60)]
        # High-resolution points 5 s apart over the last minute keep every recent 10 s bucket filled.
        for back in range(0, 55, 5):
            data.append({"MetricName": "HighRes", "Timestamp": now - timedelta(seconds=back),
                         "Value": _VALUE, "StorageResolution": 1})
        cw.put_metric_data(Namespace=namespace, MetricData=data)

    specs = {
        "std10": ("StandardRes", 10, 1),
        "std30": ("StandardRes", 30, 1),
        "hi10": ("HighRes", 10, 3),
    }
    _publish()
    names = {}
    for key, (metric, period, n) in specs.items():
        name = ctx.unique_name(f"sim2real-resolution-{key}-")
        resp = cw.put_metric_alarm(
            AlarmName=name, Namespace=namespace, MetricName=metric, Statistic="Maximum",
            Period=period, EvaluationPeriods=n, DatapointsToAlarm=n, Threshold=_THRESHOLD,
            ComparisonOperator="GreaterThanThreshold", TreatMissingData="missing",
            ActionsEnabled=False, AlarmDescription=f"sim2real resolution {key}",
            Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        )
        ctx.on_cleanup(lambda nm=name: cw.delete_alarms(AlarmNames=[nm]))
        names[key] = name
        code = resp["ResponseMetadata"]["HTTPStatusCode"]
        assert code == 200, f"PutMetricAlarm {key!r} (Period={period}) returned HTTP {code!r}"

    # AWS validates Period against {10, 20, 30, 60n}, not against the metric's storage resolution.
    for key, name in names.items():
        a = _describe(cw, name)
        assert a.get("Period") == specs[key][1], (
            f"{key!r} read back Period={a.get('Period')!r}, expected {specs[key][1]} -- a target "
            f"that silently rounds a sub-minute period up to 60 fails here"
        )

    def _tick_publish():
        _publish()

    fired = {}
    budget = _budget_s(ctx, 420.0)
    deadline = time.monotonic() + budget
    while True:
        for key, name in names.items():
            if key not in fired:
                a = _describe(cw, name)
                if a["StateValue"] == "ALARM":
                    fired[key] = a
        if len(fired) == len(names):
            break
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(
                    f"all of {sorted(names)!r} to reach ALARM: the run budget ended first; not graded"
                )
            raise AssertionError(
                f"only {sorted(fired)!r} of {sorted(names)!r} reached ALARM within {budget:.0f}s "
                f"over a series of {_VALUE} against threshold {_THRESHOLD}"
            )
        _tick_publish()
        time.sleep(1.0)

    for key in ("std10", "std30"):
        srd = json.loads(fired[key]["StateReasonData"])
        assert srd.get("period") == specs[key][1], (
            f"{key!r} StateReasonData period={srd.get('period')!r}, expected {specs[key][1]}"
        )
        stamps = [_ts(d["timestamp"]) for d in srd.get("evaluatedDatapoints", [])]
        assert stamps and all(t.second == 0 and t.microsecond == 0 for t in stamps), (
            f"{key!r} (Period={specs[key][1]} over STANDARD-resolution data) evaluated buckets "
            f"stamped {[t.isoformat() for t in stamps]!r}; standard-resolution data is stored per "
            f"minute, so every bucket the evaluator reads must start on a whole minute"
        )
    hi = json.loads(fired["hi10"]["StateReasonData"])
    hi_stamps = sorted(_ts(d["timestamp"]) for d in hi.get("evaluatedDatapoints", []))
    gaps = [(b - a).total_seconds() for a, b in zip(hi_stamps, hi_stamps[1:])]
    assert len(hi_stamps) == 3 and gaps == [10.0, 10.0], (
        f"the high-resolution Period=10 alarm evaluated buckets "
        f"{[t.isoformat() for t in hi_stamps]!r} (gaps {gaps!r}); expected three buckets exactly "
        f"10 s apart"
    )

    end = datetime.now(timezone.utc) + timedelta(seconds=30)
    start = end - timedelta(minutes=10)
    res = {r["Id"]: r for r in cw.get_metric_data(
        MetricDataQueries=[
            {"Id": m.lower(), "MetricStat": {
                "Metric": {"Namespace": namespace, "MetricName": m}, "Period": 10,
                "Stat": "Maximum"}}
            for m in ("StandardRes", "HighRes")
        ],
        StartTime=start, EndTime=end, ScanBy="TimestampAscending",
    )["MetricDataResults"]}
    std_ts = res["standardres"]["Timestamps"]
    assert std_ts and all(t.second == 0 for t in std_ts), (
        f"GetMetricData Period=10 over standard-resolution data returned timestamps "
        f"{[t.isoformat() for t in std_ts]!r}; every one must be on a whole minute"
    )
    hi_ts = res["highres"]["Timestamps"]
    hi_gaps = {(b - a).total_seconds() for a, b in zip(hi_ts, hi_ts[1:])}
    assert 10.0 in hi_gaps and any(t.second != 0 for t in hi_ts), (
        f"GetMetricData Period=10 over high-resolution data returned timestamps "
        f"{[t.isoformat() for t in hi_ts]!r}; expected 10-second buckets"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _ts(text: str) -> datetime:
    """Parse StateReasonData's 'YYYY-MM-DDTHH:MM:SS.fff+0000' timestamp form."""
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%f%z")


def _describe(cw, alarm_name):
    for page in cw.get_paginator("describe_alarms").paginate(
        AlarmNames=[alarm_name], AlarmTypes=["MetricAlarm"]
    ):
        for alarm in page.get("MetricAlarms", []):
            if alarm["AlarmName"] == alarm_name:
                return alarm
    raise AssertionError(f"alarm {alarm_name!r} is not present in DescribeAlarms")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
