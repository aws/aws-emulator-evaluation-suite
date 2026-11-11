"""alarm-composite-and-actions-ok-and-insufficient-data-functions-are-first-class."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "alarm-composite-and-actions-ok-and-insufficient-data-functions-are-first-class"
GROUP = "evaluation"
SERVICES = ["cloudwatch"]

_THRESHOLD = 50.0
_BREACH = 163.0
_CLEAR = 7.0
_STEP_BUDGET_S = 240.0
_CHECK_BUDGET_S = 900.0


# timing:real-time — metric: 10 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Create_Composite_Alarm.html
@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Composite-alarm rule functions OK(x) and INSUFFICIENT_DATA(x) track all three child states
    (not aliases for NOT ALARM(x)), and each transition's StateReason names the child's move.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Create_Composite_Alarm.html
    """
    cw = ctx.client("cloudwatch")
    started = time.monotonic()
    budget = lambda: max(5.0, min(_STEP_BUDGET_S, _CHECK_BUDGET_S - (time.monotonic() - started)))
    namespace = ctx.unique_name("sim2real/cwfunc-")
    dims = [{"Name": "Run", "Value": ctx.unique_name("run-")}]
    metric = "load"

    child = ctx.unique_name("sim2real-cwfunc-x-")
    cw.put_metric_alarm(
        AlarmName=child, Namespace=namespace, MetricName=metric, Dimensions=dims,
        Statistic="Maximum", Period=10, EvaluationPeriods=1, Threshold=_THRESHOLD,
        ComparisonOperator="GreaterThanThreshold", TreatMissingData="ignore",
        ActionsEnabled=False, Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[child]))
    child_arn = _alarm(cw, child)["AlarmArn"]

    rules = {
        "OKF": f'OK("{child}")',
        "IDF": f'INSUFFICIENT_DATA("{child}")',
        "NA": f'NOT ALARM("{child}")',
    }
    comp = {}
    for key, rule in rules.items():
        name = ctx.unique_name(f"sim2real-cwfunc-{key.lower()}-")
        cw.put_composite_alarm(
            AlarmName=name, AlarmRule=rule, ActionsEnabled=False,
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
        ctx.on_cleanup(lambda n=name: cw.delete_alarms(AlarmNames=[n]))
        comp[key] = name

    # Child state -> expected (OKF, IDF, NA). Phase 0 has no datapoints, so the child is in
    # INSUFFICIENT_DATA, where OK(x) and NOT ALARM(x) disagree.
    phases = [
        ("INSUFFICIENT_DATA", None, {"OKF": "OK", "IDF": "ALARM", "NA": "ALARM"}),
        ("OK", _CLEAR, {"OKF": "ALARM", "IDF": "OK", "NA": "ALARM"}),
        ("ALARM", _BREACH, {"OKF": "OK", "IDF": "OK", "NA": "OK"}),
    ]
    previous = None
    for index, (child_state, value, want) in enumerate(phases):
        observed_child = _wait_for(
            f"phase {index}: child to reach {child_state}"
            + (f" from real datapoints of {value}" if value is not None else " with no datapoints"),
            lambda: _alarm(cw, child),
            lambda al, s=child_state: al["StateValue"] == s,
            budget(),
            each=(lambda v=value: _put(cw, namespace, metric, dims, v)) if value is not None else None,
        )
        if value is not None:
            assert f"[{value}" in observed_child["StateReason"], (
                f"phase {index}: child's StateReason does not cite datapoint {value}: "
                f"{observed_child['StateReason']!r}"
            )
        got = _wait_for(
            f"phase {index}: composites to reach {want!r} with child in {child_state}",
            lambda: {k: _alarm(cw, n) for k, n in comp.items()},
            lambda d, w=want: {k: a["StateValue"] for k, a in d.items()} == w,
            budget(),
        )
        assert _alarm(cw, child)["StateValue"] == child_state, f"phase {index}: child drifted"
        if previous is not None:
            for key, alarm in got.items():
                if alarm["StateValue"] == previous[key]:
                    continue  # no transition this phase, so no new reason to attribute
                assert alarm["StateReason"].startswith(f"{child_arn} transitioned to {child_state}"), (
                    f"phase {index}: {key} moved {previous[key]}->{alarm['StateValue']} but its "
                    f"StateReason does not name the child's move to {child_state}: {alarm['StateReason']!r}"
                )
                data = json.loads(alarm["StateReasonData"])
                trig = {t["arn"]: t["state"]["value"] for t in data["triggeringAlarms"]}
                assert trig == {child_arn: child_state}, (
                    f"phase {index}: {key} StateReasonData.triggeringAlarms = {trig!r}"
                )
        previous = {k: a["StateValue"] for k, a in got.items()}


def _alarm(cw, name: str) -> dict:
    resp = cw.describe_alarms(AlarmNames=[name], AlarmTypes=["CompositeAlarm", "MetricAlarm"])
    found = resp["MetricAlarms"] + resp["CompositeAlarms"]
    assert len(found) == 1, f"describe_alarms({name!r}) returned {len(found)} alarms"
    return found[0]


def _put(cw, namespace: str, metric: str, dims: list, value: float) -> None:
    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[{"MetricName": metric, "Dimensions": dims, "Value": value, "StorageResolution": 1}],
    )


def _wait_for(what, fetch, pred, budget_s, each=None, interval_s=5.0):
    deadline = time.monotonic() + budget_s
    last = None
    while True:
        if each is not None:
            each()
        last = fetch()
        if pred(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {budget_s:.0f}s waiting for {what}; last={last!r}")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
