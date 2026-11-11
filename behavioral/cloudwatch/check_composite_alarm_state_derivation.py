"""composite-alarm-state-derivation."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "composite-alarm-state-derivation"
GROUP = 'alarms'
SERVICES = ['cloudwatch']

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:metrics", "plane:control")
def run(ctx) -> None:
    """A composite alarm's state is derived from its AlarmRule evaluating the child alarm,
    in both directions -- it must not merely latch ALARM once, and it must not already be
    ALARM before the child ever fires."""
    cw = ctx.client("cloudwatch")
    child_name = ctx.unique_name("sim2real-behav-cwprobe-child-")
    composite_name = ctx.unique_name("sim2real-behav-cwprobe-composite-")
    namespace = ctx.unique_name("sim2real-behav-cwprobe-ns-")
    ctx.on_cleanup(lambda _n=child_name: cw.delete_alarms(AlarmNames=[_n]))
    ctx.on_cleanup(lambda _n=composite_name: cw.delete_alarms(AlarmNames=[_n]))

    cw.put_metric_alarm(
        AlarmName=child_name,
        Namespace=namespace,
        MetricName="Manual",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
    )
    cw.put_composite_alarm(
        AlarmName=composite_name,
        AlarmRule=f'ALARM("{child_name}")',
    )

    def probe_composite():
        return cw.describe_alarms(AlarmNames=[composite_name], AlarmTypes=["CompositeAlarm"])

    initial = _poll_until(
        probe_composite,
        lambda r: len(r.get("CompositeAlarms", [])) > 0,
        timeout_s=20,
        interval_s=2,
    )
    baseline = initial["CompositeAlarms"][0]["StateValue"]
    assert baseline != "ALARM", (
        f"composite alarm was already ALARM before its child ever fired, got {baseline!r} "
        "-- this would let a target that always reports ALARM pass trivially"
    )

    cw.set_alarm_state(AlarmName=child_name, StateValue="ALARM", StateReason="drive composite")

    resp = _poll_until(
        probe_composite,
        lambda r: r.get("CompositeAlarms") and r["CompositeAlarms"][0]["StateValue"] == "ALARM",
        timeout_s=30,
        interval_s=2,
    )
    assert resp["CompositeAlarms"][0]["StateValue"] == "ALARM", (
        "composite alarm did not transition to ALARM after child alarm entered ALARM"
    )

    cw.set_alarm_state(AlarmName=child_name, StateValue="OK", StateReason="clear composite")

    resp = _poll_until(
        probe_composite,
        lambda r: r.get("CompositeAlarms") and r["CompositeAlarms"][0]["StateValue"] == "OK",
        timeout_s=30,
        interval_s=2,
    )
    assert resp["CompositeAlarms"][0]["StateValue"] == "OK", (
        "composite alarm did not re-derive OK after its child alarm cleared -- a target that "
        "only ever latches ALARM once would fail here"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
