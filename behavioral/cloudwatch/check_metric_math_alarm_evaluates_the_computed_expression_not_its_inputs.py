"""metric-math-alarm-evaluates-the-computed-expression-not-its-inputs."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "metric-math-alarm-evaluates-the-computed-expression-not-its-inputs"
GROUP = "metric-math"
SERVICES = ["cloudwatch"]

#: The alarm watches an error RATE in percent. Both source values stay far below the threshold at
#: all times, so a target that evaluates either source metric instead of the expression can never
#: reach ALARM -- which is the whole discrimination.
_THRESHOLD = 50.0
_REQUESTS = 20.0
_ERRORS_OK = 5.0  # 5/20*100 == 25.0  -> below 50, and 5 and 20 are also below 50
_ERRORS_BREACH = 15.0  # 15/20*100 == 75.0 -> above 50, while 15 and 20 are still below 50
_RATE_OK = 25.0
_RATE_BREACH = 75.0


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """An alarm over a Metrics array is evaluated against the computed expression, not its inputs:
    every raw source value stays below the threshold while the expression crosses it, and the
    mutually exclusive or ReturnData-less forms are rejected."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealMathAlarmNs")
    alarm_name = ctx.unique_name("sim2real-mathalarm-")
    rejected_name = ctx.unique_name("sim2real-mathalarm-rejected-")

    errors_value = [_ERRORS_OK]
    published: list = [None]

    def _publish() -> None:
        # Once per period and value: Stat=Maximum makes a repeat inside one minute redundant.
        stamp = datetime.now(timezone.utc).replace(second=0, microsecond=0)
        if published[0] == (stamp, errors_value[0]):
            return
        published[0] = (stamp, errors_value[0])
        cw.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": "Errors",
                    "Timestamp": stamp,
                    "Value": errors_value[0],
                    "Unit": "Count",
                },
                {
                    "MetricName": "Requests",
                    "Timestamp": stamp,
                    "Value": _REQUESTS,
                    "Unit": "Count",
                },
            ],
        )

    def _math_queries() -> list[dict]:
        return [
            {
                "Id": "errors",
                "MetricStat": {
                    "Metric": {"Namespace": namespace, "MetricName": "Errors"},
                    "Period": 60,
                    "Stat": "Maximum",
                },
                "ReturnData": False,
            },
            {
                "Id": "requests",
                "MetricStat": {
                    "Metric": {"Namespace": namespace, "MetricName": "Requests"},
                    "Period": 60,
                    "Stat": "Maximum",
                },
                "ReturnData": False,
            },
            {
                "Id": "rate",
                "Expression": "(errors / requests) * 100",
                "Label": "ErrorRatePercent",
                "ReturnData": True,
            },
        ]

    # Seed one full period BEFORE the alarm exists, so its first evaluation has data to read.
    _publish()

    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Metrics=_math_queries(),
        Threshold=_THRESHOLD,
        ComparisonOperator="GreaterThanThreshold",
        EvaluationPeriods=1,
        DatapointsToAlarm=1,
        # 'ignore' keeps the current state over a period with no data yet, so every transition
        # below is decided by a published period, never by an empty one.
        TreatMissingData="ignore",
        ActionsEnabled=False,
        AlarmDescription="sim2real depth: the evaluator must run the expression, not its inputs",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    # --- the alarm has no scalar metric identity at all -------------------------------------- #
    created = _describe(cw, alarm_name)
    returned = {q["Id"]: q for q in created["Metrics"]}
    assert set(returned) == {"errors", "requests", "rate"}, (
        f"the alarm read back Metrics ids {sorted(returned)!r}, expected "
        f"['errors', 'rate', 'requests'] -- all three queries must survive the round trip or the "
        f"evaluator has nothing to compute from"
    )
    assert returned["rate"]["Expression"] == "(errors / requests) * 100", (
        f"the watched expression read back as {returned['rate'].get('Expression')!r}, expected "
        f"'(errors / requests) * 100'"
    )
    assert returned["rate"]["ReturnData"] is True, (
        f"the expression query's ReturnData read back {returned['rate'].get('ReturnData')!r}, "
        f"expected True -- it is the flag that designates which series the alarm watches"
    )
    for source in ("errors", "requests"):
        assert returned[source].get("ReturnData") is False, (
            f"source query {source!r} read back ReturnData "
            f"{returned[source].get('ReturnData')!r}, expected False"
        )
    # Narrowed deliberately to the three keys that would mean the target collapsed the expression
    # to a single metric. `Period` and `ExtendedStatistic` are excluded because a server-side
    # default populating them would fail a CORRECT target for a cosmetic reason.
    for scalar in ("MetricName", "Namespace", "Statistic"):
        assert scalar not in created, (
            f"the alarm reports a scalar {scalar}={created.get(scalar)!r}. The API reference says "
            f"the Metrics parameter cannot be combined with Namespace/MetricName/Dimensions/"
            f"Period/Unit/Statistic/ExtendedStatistic, so a math alarm has no scalar metric "
            f"identity -- reporting one means the target collapsed the expression to one metric"
        )
    # The sources hold data already, so the first evaluation may land before this read; the start
    # state is proven by the oldest history item below.
    assert created["StateValue"] in ("INSUFFICIENT_DATA", "OK"), (
        f"a freshly created alarm over a {_RATE_OK} expression reported "
        f"{created['StateValue']!r}; it starts in INSUFFICIENT_DATA and may only evaluate to OK"
    )

    # --- leg A: the expression evaluates to 25.0, which is below the threshold ---------------- #
    ok = _poll_until(
        ctx,
        lambda: _describe(cw, alarm_name),
        lambda a: a["StateValue"] == "OK",
        timeout_s=300.0,
        interval_s=2.0,
        description=(
            f"alarm {alarm_name!r} produced an evaluated OK from the expression value {_RATE_OK} "
            f"(= {_ERRORS_OK}/{_REQUESTS}*100)"
        ),
        on_iteration=_publish,
    )
    _assert_evaluated_value(ok, _RATE_OK, "OK")

    # --- leg B: the expression crosses 50 while every raw input stays below it ---------------- #
    errors_value[0] = _ERRORS_BREACH
    _publish()
    fired = _poll_until(
        ctx,
        lambda: _describe(cw, alarm_name),
        lambda a: a["StateValue"] == "ALARM",
        timeout_s=300.0,
        interval_s=2.0,
        description=(
            f"alarm {alarm_name!r} fired once the expression reached {_RATE_BREACH} "
            f"(= {_ERRORS_BREACH}/{_REQUESTS}*100); no set_alarm_state call exists in this file"
        ),
        on_iteration=_publish,
    )
    _assert_evaluated_value(fired, _RATE_BREACH, "ALARM")
    srd = json.loads(fired["StateReasonData"])
    assert srd["threshold"] == _THRESHOLD, (
        f"the ALARM decision recorded threshold {srd['threshold']!r}, expected {_THRESHOLD!r} "
        f"echoed from the alarm's own configuration"
    )

    # --- B1 terminal read: an independent operation at the destination ------------------------ #
    # DescribeAlarmHistory is neither the mutation (PutMetricData) nor the poll (DescribeAlarms),
    # and it is the only server-side record that the transition happened rather than being
    # reported.
    updates = _poll_until(
        ctx,
        lambda: _state_updates(cw, alarm_name),
        lambda items: any(_new_state(i) == "ALARM" for i in items),
        timeout_s=120.0,
        interval_s=2.0,
        description=f"a StateUpdate history item recording the ALARM transition on {alarm_name!r}",
    )
    entry = next(json.loads(i["HistoryData"]) for i in updates if _new_state(i) == "ALARM")
    assert entry["oldState"]["stateValue"] == "OK", (
        f"the ALARM transition recorded in history came from "
        f"{entry['oldState']['stateValue']!r}; it must come from the OK asserted in leg A, which "
        f"is what makes the two legs one alarm's history rather than two unrelated observations"
    )
    first = json.loads(updates[-1]["HistoryData"])
    assert (first["oldState"]["stateValue"], first["newState"]["stateValue"]) == (
        "INSUFFICIENT_DATA",
        "OK",
    ), (
        f"the alarm's first StateUpdate went {first['oldState']['stateValue']!r} -> "
        f"{first['newState']['stateValue']!r}; every new CloudWatch alarm starts in "
        f"INSUFFICIENT_DATA regardless of data already present in the sources"
    )
    # Already a nested OBJECT, so no json.loads: the HistoryData string was decoded above, and inside
    # it `newState.stateReasonData` is structured JSON rather than a re-encoded string. Only the
    # top-level DescribeAlarms field of the same name (used at the other two sites here) is a string.
    # Decoding twice raised "the JSON object must be str, bytes or bytearray, not dict".
    history_values = entry["newState"]["stateReasonData"]["recentDatapoints"]
    assert any(abs(float(v) - _RATE_BREACH) < 1e-6 for v in history_values), (
        f"the history entry's own recentDatapoints are {history_values!r} and do not contain the "
        f"computed {_RATE_BREACH}; the transition was recorded against something other than the "
        f"expression result"
    )

    # --- negative 1: Metrics and the scalar metric parameters are mutually exclusive ---------- #
    # Always-invalid-input class: there is no restore beat, because the combination can never
    # become legal. The positive control is the alarm created above from the identical array.
    combo_error = _error(
        lambda: cw.put_metric_alarm(
            AlarmName=rejected_name,
            Metrics=_math_queries(),
            Namespace=namespace,
            MetricName="Errors",
            Statistic="Maximum",
            Period=60,
            Threshold=_THRESHOLD,
            ComparisonOperator="GreaterThanThreshold",
            EvaluationPeriods=1,
        ),
        subject="Metrics combined with Namespace/MetricName/Statistic/Period",
    )
    assert combo_error == ("ValidationError", "MetricName should not be set if list of Metrics is set."), (
        f"combining Metrics with the scalar metric parameters raised {combo_error!r}, expected "
        f"that exact ValidationError -- the two ways of naming what an alarm watches are "
        f"documented as mutually exclusive"
    )
    assert _describe_all(cw, [rejected_name]) == [], (
        f"the rejected PutMetricAlarm created an alarm anyway: "
        f"{_describe_all(cw, [rejected_name])!r}"
    )

    # --- negative 2: no item designates itself as the watched series -------------------------- #
    no_return = [dict(q) for q in _math_queries()]
    for q in no_return:
        q["ReturnData"] = False
    no_return_error = _error(
        lambda: cw.put_metric_alarm(
            AlarmName=rejected_name,
            Metrics=no_return,
            Threshold=_THRESHOLD,
            ComparisonOperator="GreaterThanThreshold",
            EvaluationPeriods=1,
        ),
        subject="a Metrics array with no ReturnData=True item",
    )
    assert no_return_error == ("ValidationError", "Exactly one element of the metrics list should return data."), (
        f"a Metrics array where every ReturnData is False raised {no_return_error!r}, expected "
        f"that exact ValidationError -- exactly one Expression item must carry ReturnData=True, "
        f"and without it there is no series for the alarm to watch"
    )
    assert _describe_all(cw, [rejected_name]) == [], (
        f"the ReturnData-less PutMetricAlarm created an alarm anyway: "
        f"{_describe_all(cw, [rejected_name])!r}"
    )

    # --- positive control: the legal form still works after both rejections ------------------- #
    still_there = _describe(cw, alarm_name)
    assert still_there["StateValue"] == "ALARM", (
        f"after the two rejections the working math alarm reports "
        f"{still_there['StateValue']!r}, expected the ALARM it had reached -- without this leg "
        f"'rejects the illegal combination' is indistinguishable from 'rejects every "
        f"PutMetricAlarm'"
    )

    # --- B9: the delete proves gone and unusable ---------------------------------------------- #
    cw.delete_alarms(AlarmNames=[alarm_name])
    assert _describe_all(cw, [alarm_name]) == [], (
        f"DeleteAlarms left {_describe_all(cw, [alarm_name])!r} behind"
    )
    dead_error = _error(
        lambda: cw.set_alarm_state(
            AlarmName=alarm_name, StateValue="OK", StateReason="post-delete mutation probe"
        ),
        subject=f"SetAlarmState on the deleted alarm {alarm_name!r}",
    )
    assert dead_error == ("ResourceNotFound", ""), (
        f"a mutation on the deleted alarm raised {dead_error!r}, expected that exact ResourceNotFound -- the "
        f"same SetAlarmState shape succeeds against a live alarm, so the id must now be dead"
    )


# ===== helpers =====
def _assert_evaluated_value(alarm: dict, expected: float, state: str) -> None:
    """The engine's own recentDatapoints must hold the EXPRESSION value, not a source metric's."""
    srd = json.loads(alarm["StateReasonData"])
    window = srd["recentDatapoints"]
    assert len(window) == 1, (
        f"the {state} verdict evaluated {len(window)} datapoints {window!r}; EvaluationPeriods=1 "
        f"means exactly one"
    )
    got = float(window[0])
    assert abs(got - expected) < 1e-6, (
        f"the {state} verdict was reached over the value {got!r}; expected the expression result "
        f"{expected!r}. The source metrics held {_ERRORS_OK}/{_ERRORS_BREACH} and {_REQUESTS} in "
        f"this run, so a value equal to one of those means the evaluator read a source metric "
        f"instead of computing '(errors / requests) * 100'"
    )


def _describe_all(cw, names):
    """Every metric alarm in *names*, via a paginated DescribeAlarms.

    Paginated because other alarms in the account can push a result off page one.
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


def _new_state(item) -> str:
    return json.loads(item["HistoryData"]).get("newState", {}).get("stateValue", "")


def _error(fn, *, subject: str) -> tuple[str, str]:
    """Call fn(); return the botocore error (Code, Message). An unexpected SUCCESS raises.

    Returning a falsy sentinel would let an over-permissive target turn acceptance into a plain
    code mismatch, which is the weaker verdict.
    """
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS refuses {subject}, but the call SUCCEEDED and returned {result!r}"
    )


def _poll_until(ctx, probe, predicate, *, timeout_s, interval_s, description, on_iteration=None):
    """Poll probe() until predicate(result); FAIL on exhaustion, never skip."""
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
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
