"""alarm-missing-data-and-m-of-n-evaluation-horizon-beyond-day-or-week-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "alarm-missing-data-and-m-of-n-evaluation-horizon-beyond-day-or-week-rejected"
GROUP = "validation"
SERVICES = ["cloudwatch"]

# The model only bounds each field at min 1; real AWS caps their product, by Period regime.
_DAY = (
    "Metrics cannot be checked across more than a day (EvaluationPeriods * Period must be <= 86400) "
    "for alarms using period < 3600"
)
_WEEK = (
    "Metrics cannot be checked across more than a week (EvaluationPeriods * Period must be <= "
    "604800) for alarms using period >= 3600"
)


@tags(
    "axis:rejection",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
    "cap:c1",
)
def run(ctx) -> None:
    """PutMetricAlarm refuses EvaluationPeriods x Period over a day (Period < 3600) or a week
    (Period >= 3600) with an exact ValidationError, writing nothing; legal neighbours are stored.
    """
    cw = ctx.client("cloudwatch")
    alarm = ctx.unique_name("sim2real-horizon-")
    namespace = ctx.unique_name("Sim2RealHorizon")
    base = dict(
        Namespace=namespace,
        MetricName="Horizon",
        Statistic="Sum",
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        DatapointsToAlarm=1,
        TreatMissingData="notBreaching",
        ActionsEnabled=False,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )

    # Positive control: exactly one day at a one-minute period is legal.
    cw.put_metric_alarm(AlarmName=alarm, Period=60, EvaluationPeriods=1440, **base)
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm]))
    assert _stored(cw, alarm) == (60, 1440), f"the one-day alarm stored {_stored(cw, alarm)!r}"

    legs = [
        # (period, periods past the ceiling, message, the legal neighbour to prove the boundary)
        (60, 1441, _DAY, 1440),
        (300, 289, _DAY, 288),
        (60, 1500, _DAY, None),     # 90000 s at a sub-hour period: refused ...
        (3600, 169, _WEEK, 168),
        (86400, 8, _WEEK, 7),
    ]
    for period, too_many, message, legal in legs:
        before = _stored(cw, alarm)
        code, msg = _error(lambda: cw.put_metric_alarm(
            AlarmName=alarm, Period=period, EvaluationPeriods=too_many, **base))
        assert code == "ValidationError", (
            f"Period={period} x EvaluationPeriods={too_many} = {period * too_many} s must be refused "
            f"with ValidationError, got {code!r} ({msg!r})"
        )
        assert msg == message, (
            f"Period={period} x EvaluationPeriods={too_many}: the refusal must state the "
            f"{'day' if message is _DAY else 'week'} rule verbatim, got {msg!r}"
        )
        assert _stored(cw, alarm) == before, (
            f"the refused update Period={period} x {too_many} changed the stored alarm from "
            f"{before!r} to {_stored(cw, alarm)!r}; a refusal must not partially write"
        )
        if legal is not None:
            cw.put_metric_alarm(AlarmName=alarm, Period=period, EvaluationPeriods=legal, **base)
            assert _stored(cw, alarm) == (period, legal), (
                f"the legal neighbour Period={period} x {legal} = {period * legal} s was not stored: "
                f"{_stored(cw, alarm)!r}"
            )

    # ... while the same 90000 s at Period=3600 is inside the week regime and is ACCEPTED.
    cw.put_metric_alarm(AlarmName=alarm, Period=3600, EvaluationPeriods=25, **base)
    assert _stored(cw, alarm) == (3600, 25), (
        f"25 x 3600 = 90000 s is legal in the Period>=3600 regime, stored {_stored(cw, alarm)!r}"
    )

    # A rejected CREATE creates nothing.
    ghost = ctx.unique_name("sim2real-horizon-ghost-")
    code, msg = _error(lambda: cw.put_metric_alarm(
        AlarmName=ghost, Period=300, EvaluationPeriods=289, **base))
    if code == _SUCCEEDED:
        ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[ghost]))
    assert code == "ValidationError" and msg == _DAY, (
        f"creating a 300 x 289 alarm must be refused with the day rule, got {code!r} ({msg!r})"
    )
    assert cw.describe_alarms(AlarmNames=[ghost])["MetricAlarms"] == [], (
        f"the refused create left alarm {ghost!r} behind"
    )


_SUCCEEDED = "<no error: the call SUCCEEDED>"


def _error(fn):
    """Call fn(); return (code, message) of a ClientError, or a non-code sentinel on success."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    return _SUCCEEDED, "the target accepted a configuration real AWS refuses"


def _stored(cw, alarm_name):
    alarms = cw.describe_alarms(AlarmNames=[alarm_name], AlarmTypes=["MetricAlarm"])["MetricAlarms"]
    assert len(alarms) == 1, f"expected exactly one alarm {alarm_name!r}, got {alarms!r}"
    return alarms[0]["Period"], alarms[0]["EvaluationPeriods"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
