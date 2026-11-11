"""deep-cloudwatch-1-cw-warmup-wall-clock-window-gates-evaluation-and-rejects-period-120."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "deep-cloudwatch-1-cw-warmup-wall-clock-window-gates-evaluation-and-rejects-period-120"
GROUP = "alerting"
SERVICES = ["cloudwatch"]

_PERIOD = 300
_THRESHOLD = 10.0
_BREACH = 100.0
_WALL_CLOCK = {"WallClockWindow": {"Timezone": "UTC"}}
_SLIDING = {"SlidingWindow": {}}
_BAD_PERIOD_CODE = "ValidationError"
_BAD_PERIOD_MESSAGE = "Wall Clock evaluation period must be 1 minute, 5 minutes, 1 hour, 1 day or 1 week."


# timing:real-time — metric: 217 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:rejection", "cap:c1", "cap:c4", "concern:metrics", "concern:negative-classes",
      "dp:api", "plane:control", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Twin Period=300 alarms on one series: the sliding one alarms inside the open period, the
    wall-clock one only after the aligned period closes, from exactly the boundary. Period=120 is
    refused (exact ValidationError) for wall-clock only; neither reports EvaluationState.
    """
    cw = ctx.client("cloudwatch")
    # CloudWatch has no DeleteMetric, so the namespace is unique per run and ages out.
    namespace = ctx.unique_name("Sim2RealWallClockNs")
    metric = "WindowSignal"
    tags_kv = [
        {"Key": "sim2real:managed", "Value": "true"},
        {"Key": "sim2real:check", "Value": CHECK},
    ]
    common = dict(
        Namespace=namespace,
        MetricName=metric,
        Statistic="Maximum",
        EvaluationPeriods=1,
        DatapointsToAlarm=1,
        Threshold=_THRESHOLD,
        ComparisonOperator="GreaterThanThreshold",
        ActionsEnabled=False,
        Tags=tags_kv,
    )

    # The Smithy model types Period as a plain integer; the 1m/5m/1h/1d/1w rule is wall-clock only.
    bad_name = ctx.unique_name("sim2real-wallclock-p120-")
    ctx.on_cleanup(lambda: ctx.client("cloudwatch").delete_alarms(AlarmNames=[bad_name]))
    code, message, status = _error(
        lambda: cw.put_metric_alarm(
            AlarmName=bad_name, Period=120, EvaluationWindow=_WALL_CLOCK, **common
        )
    )
    assert code == _BAD_PERIOD_CODE, (
        f"Period=120 with a WallClockWindow returned error code {code!r}, expected "
        f"{_BAD_PERIOD_CODE!r} (a wall-clock period must be 1 minute, 5 minutes, 1 hour, 1 day or "
        f"1 week)"
    )
    assert message == _BAD_PERIOD_MESSAGE, (
        f"Period=120 with a WallClockWindow returned message {message!r}, expected "
        f"{_BAD_PERIOD_MESSAGE!r}"
    )
    assert status == 400, f"the refusal carried HTTP status {status!r}, expected 400"
    leaked = cw.describe_alarms(AlarmNames=[bad_name], AlarmTypes=["MetricAlarm"])["MetricAlarms"]
    assert leaked == [], f"the refused wall-clock alarm exists anyway: {leaked!r}"

    ctl_name = ctx.unique_name("sim2real-sliding-p120-")
    cw.put_metric_alarm(AlarmName=ctl_name, Period=120, EvaluationWindow=_SLIDING, **common)
    ctx.on_cleanup(lambda: ctx.client("cloudwatch").delete_alarms(AlarmNames=[ctl_name]))
    ctl = _alarm(cw, ctl_name)
    assert ctl["Period"] == 120 and ctl.get("EvaluationWindow") == _SLIDING, (
        f"the SlidingWindow control at Period=120 read back Period {ctl['Period']!r} and "
        f"EvaluationWindow {ctl.get('EvaluationWindow')!r}; the refusal above must be specific to "
        f"the wall-clock window"
    )

    # Start just after a 300s UTC boundary so the wall-clock period is still open.
    _poll_until(
        lambda: datetime.now(timezone.utc).timestamp() % _PERIOD,
        lambda into: 5.0 <= into <= 150.0,
        timeout_s=float(_PERIOD) + 30.0,
        interval_s=2.0,
        description="the UTC clock reached 5-150s past a 300s boundary",
    )

    def _tick() -> None:
        cw.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": metric,
                    "Timestamp": datetime.now(timezone.utc),
                    "Value": _BREACH,
                    "Unit": "Count",
                }
            ],
        )

    _tick()
    wc_name = ctx.unique_name("sim2real-wallclock-p300-")
    sl_name = ctx.unique_name("sim2real-sliding-p300-")
    cw.put_metric_alarm(AlarmName=wc_name, Period=_PERIOD, EvaluationWindow=_WALL_CLOCK, **common)
    ctx.on_cleanup(lambda: ctx.client("cloudwatch").delete_alarms(AlarmNames=[wc_name]))
    cw.put_metric_alarm(AlarmName=sl_name, Period=_PERIOD, EvaluationWindow=_SLIDING, **common)
    ctx.on_cleanup(lambda: ctx.client("cloudwatch").delete_alarms(AlarmNames=[sl_name]))

    wc0 = _alarm(cw, wc_name)
    assert wc0.get("EvaluationWindow") == _WALL_CLOCK, (
        f"the wall-clock arm read back EvaluationWindow {wc0.get('EvaluationWindow')!r}"
    )
    # The boundary is taken from the SERVER's clock, not ours.
    created = wc0["AlarmConfigurationUpdatedTimestamp"]
    boundary = datetime.fromtimestamp(
        created.timestamp() - (created.timestamp() % _PERIOD), tz=timezone.utc
    )
    closes = boundary + timedelta(seconds=_PERIOD)

    sl = _poll_until(
        lambda: _alarm(cw, sl_name),
        lambda a: a["StateValue"] == "ALARM",
        timeout_s=max((closes - datetime.now(timezone.utc)).total_seconds(), 1.0),
        interval_s=5.0,
        on_iteration=_tick,
        description=(
            f"the SlidingWindow twin {sl_name!r} reached ALARM before the wall-clock window "
            f"{boundary.isoformat()} .. {closes.isoformat()} closed"
        ),
    )
    wc_mid = _alarm(cw, wc_name)
    assert wc_mid["StateValue"] == "INSUFFICIENT_DATA", (
        f"the wall-clock twin reports {wc_mid['StateValue']!r} (reason "
        f"{wc_mid.get('StateReason')!r}) while its window {boundary.isoformat()} .. "
        f"{closes.isoformat()} is still open and its sliding twin has already alarmed; it may "
        f"evaluate only a closed period"
    )
    sl_srd = json.loads(sl["StateReasonData"])
    sl_start = _ts(sl_srd["startDate"])
    sl_query = _ts(sl_srd["queryDate"])
    assert sl_srd["period"] == _PERIOD, f"sliding StateReasonData period {sl_srd['period']!r}"
    assert sl_query < closes, (
        f"the sliding twin's queryDate {sl_query.isoformat()} is not before {closes.isoformat()}"
    )
    assert sl_start < boundary, (
        f"the sliding twin evaluated from {sl_start.isoformat()}, expected a range reaching back "
        f"before the {boundary.isoformat()} boundary (a rolling window ending at "
        f"{sl_query.isoformat()})"
    )
    assert sl_start.second == 0 and sl_start.microsecond == 0, (
        f"the sliding twin's startDate {sl_start.isoformat()} is not minute-aligned"
    )
    sl_points = [_ts(p["timestamp"]) for p in sl_srd["evaluatedDatapoints"]]
    assert sl_points == [sl_start], (
        f"the sliding twin's evaluatedDatapoints timestamps {sl_points!r} are not exactly its "
        f"startDate {sl_start.isoformat()}"
    )
    assert "EvaluationState" not in sl, (
        f"the sliding twin reports EvaluationState {sl.get('EvaluationState')!r}"
    )

    wc = _poll_until(
        lambda: _alarm(cw, wc_name),
        lambda a: a["StateValue"] == "ALARM",
        timeout_s=max((closes - datetime.now(timezone.utc)).total_seconds(), 0.0) + 300.0,
        interval_s=10.0,
        on_iteration=_tick,
        description=(
            f"the WallClockWindow twin {wc_name!r} reached ALARM once the window "
            f"{boundary.isoformat()} .. {closes.isoformat()} closed"
        ),
    )
    wc_srd = json.loads(wc["StateReasonData"])
    wc_start = _ts(wc_srd["startDate"])
    wc_query = _ts(wc_srd["queryDate"])
    assert wc_srd["period"] == _PERIOD, f"wall-clock StateReasonData period {wc_srd['period']!r}"
    assert wc_start == boundary, (
        f"the wall-clock twin evaluated from {wc_start.isoformat()}, expected exactly the UTC "
        f"boundary {boundary.isoformat()}"
    )
    wc_points = [_ts(p["timestamp"]) for p in wc_srd["evaluatedDatapoints"]]
    assert wc_points == [boundary], (
        f"the wall-clock twin's evaluatedDatapoints timestamps {wc_points!r}, expected exactly "
        f"[{boundary.isoformat()}]"
    )
    assert wc_query >= closes, (
        f"the wall-clock twin evaluated at {wc_query.isoformat()}, before its window closed at "
        f"{closes.isoformat()}"
    )
    assert wc["StateUpdatedTimestamp"] >= closes, (
        f"the wall-clock twin transitioned at {wc['StateUpdatedTimestamp'].isoformat()}, before "
        f"its window closed at {closes.isoformat()}"
    )
    assert wc_start != sl_start, (
        f"the two twins evaluated the same range starting {wc_start.isoformat()}; EvaluationWindow "
        f"must change which datapoints are evaluated"
    )
    assert "EvaluationState" not in wc, (
        f"the wall-clock twin reports EvaluationState {wc.get('EvaluationState')!r}"
    )
    assert "EvaluationState" not in _alarm(cw, sl_name), "the sliding twin gained an EvaluationState"


def _error(fn):
    """Return (code, message, http_status) of the ClientError fn raises. A SUCCESS is an AssertionError."""
    try:
        fn()
    except Exception as exc:  # botocore ClientError, or a target's equivalent
        resp = getattr(exc, "response", None)
        assert isinstance(resp, dict), f"call raised a non-service error {exc!r}"
        error = resp.get("Error", {})
        return (
            error.get("Code"),
            error.get("Message", ""),
            resp.get("ResponseMetadata", {}).get("HTTPStatusCode"),
        )
    raise AssertionError("the call SUCCEEDED; real AWS rejects it")


def _ts(value: str) -> datetime:
    """Parse StateReasonData's 'YYYY-MM-DDTHH:MM:SS.mmm+0000' timestamp form."""
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%f%z")


def _alarm(cw, name):
    for page in cw.get_paginator("describe_alarms").paginate(
        AlarmNames=[name], AlarmTypes=["MetricAlarm"]
    ):
        for alarm in page.get("MetricAlarms", []):
            if alarm["AlarmName"] == name:
                return alarm
    raise AssertionError(f"metric alarm {name!r} is not present in DescribeAlarms")


def _poll_until(probe, predicate, *, timeout_s, interval_s, description, on_iteration=None):
    """Poll probe() until predicate(result); FAIL on exhaustion, never skip."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} did not happen within {timeout_s:.0f}s; last observation {last!r}"
            )
        if on_iteration is not None:
            on_iteration()
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
