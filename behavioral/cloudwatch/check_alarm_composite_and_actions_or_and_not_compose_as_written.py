"""alarm-composite-and-actions-or-and-not-compose-as-written."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "alarm-composite-and-actions-or-and-not-compose-as-written"
GROUP = "evaluation"
SERVICES = ["cloudwatch"]

_THRESHOLD = 50.0
_BREACH = 149.0
_CLEAR = 5.0
_STEP_BUDGET_S = 240.0
_CHECK_BUDGET_S = 1200.0


# timing:real-time — metric: 10 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Create_Composite_Alarm.html
@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Composites ALARM(a) OR ALARM(b), NOT ALARM(a) and ALARM(a) AND NOT ALARM(b) each follow their
    truth table as published datapoints (no forced state) move children a/b through
    INSUFFICIENT_DATA/INSUFFICIENT_DATA, ALARM/OK, ALARM/ALARM and OK/ALARM."""
    cw = ctx.client("cloudwatch")
    started = time.monotonic()
    budget = lambda: max(5.0, min(_STEP_BUDGET_S, _CHECK_BUDGET_S - (time.monotonic() - started)))
    namespace = ctx.unique_name("sim2real/cwbool-")
    dims = [{"Name": "Run", "Value": ctx.unique_name("run-")}]

    child = {}
    for key in ("a", "b"):
        name = ctx.unique_name(f"sim2real-cwbool-{key}-")
        cw.put_metric_alarm(
            AlarmName=name, Namespace=namespace, MetricName=f"metric-{key}", Dimensions=dims,
            Statistic="Maximum", Period=10, EvaluationPeriods=1, Threshold=_THRESHOLD,
            ComparisonOperator="GreaterThanThreshold", TreatMissingData="ignore",
            ActionsEnabled=False, Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
        ctx.on_cleanup(lambda n=name: cw.delete_alarms(AlarmNames=[n]))
        child[key] = name
    a, b = child["a"], child["b"]

    rules = {
        "OR": f'ALARM("{a}") OR ALARM("{b}")',
        "NOT": f'NOT ALARM("{a}")',
        "MIX": f'ALARM("{a}") AND NOT ALARM("{b}")',
    }
    comp = {}
    for key, rule in rules.items():
        name = ctx.unique_name(f"sim2real-cwbool-{key.lower()}-")
        cw.put_composite_alarm(
            AlarmName=name, AlarmRule=rule, ActionsEnabled=False,
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
        ctx.on_cleanup(lambda n=name: cw.delete_alarms(AlarmNames=[n]))
        comp[key] = name
    for key, rule in rules.items():
        stored = _alarm(cw, comp[key])["AlarmRule"]
        assert stored == rule, f"{key} AlarmRule stored as {stored!r}, expected {rule!r}"

    phases = [
        ({a: "INSUFFICIENT_DATA", b: "INSUFFICIENT_DATA"}, {}, {"OR": "OK", "NOT": "ALARM", "MIX": "OK"}),
        ({a: "ALARM", b: "OK"}, {"metric-a": _BREACH, "metric-b": _CLEAR}, {"OR": "ALARM", "NOT": "OK", "MIX": "ALARM"}),
        ({a: "ALARM", b: "ALARM"}, {"metric-b": _BREACH}, {"OR": "ALARM", "NOT": "OK", "MIX": "OK"}),
        ({a: "OK", b: "ALARM"}, {"metric-a": _CLEAR}, {"OR": "ALARM", "NOT": "ALARM", "MIX": "OK"}),
    ]
    for index, (want_children, feed, want_comp) in enumerate(phases):
        def pump(feed=feed):
            for metric, value in feed.items():
                _put(cw, namespace, metric, dims, value)

        _wait_for(
            f"phase {index}: children to reach {want_children!r} from real datapoints",
            lambda: {n: _alarm(cw, n)["StateValue"] for n in (a, b)},
            lambda got, w=want_children: got == w,
            budget(),
            each=pump if feed else None,
        )
        got = _wait_for(
            f"phase {index}: composites to reach {want_comp!r} with children {want_children!r}",
            lambda: {k: _alarm(cw, n)["StateValue"] for k, n in comp.items()},
            lambda got, w=want_comp: got == w,
            budget(),
        )
        # The children are still in the phase's states: the composite result is for THIS input.
        now_children = {n: _alarm(cw, n)["StateValue"] for n in (a, b)}
        assert now_children == want_children, (
            f"phase {index}: children drifted to {now_children!r} while composites read {got!r}"
        )


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
