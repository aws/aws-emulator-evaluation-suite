"""composite-alarm-server-side-evaluation."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "composite-alarm-server-side-evaluation"
GROUP = 'alarms'
SERVICES = ['cloudwatch']

_METRIC_ALARM_DEFAULTS = dict(
    Namespace="AWS/EC2",
    MetricName="CPUUtilization",
    Statistic="Average",
    Period=60,
    EvaluationPeriods=1,
    Threshold=80.0,
    ComparisonOperator="GreaterThanThreshold",
)

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
    """A composite over two OK children evaluates to OK and flips to ALARM when one child is set to
    ALARM, with no SetAlarmState on the composite; a client-forced OK on the composite does not stick
    once another child changes state: it reads ALARM again."""
    cw = ctx.client("cloudwatch")

    alarm_tags = [{"Key": "sim2real", "Value": "audit"}]
    leaf1 = ctx.unique_name("sim2real-behav-cwprobe-leaf1-")
    leaf2 = ctx.unique_name("sim2real-behav-cwprobe-leaf2-")
    cw.put_metric_alarm(AlarmName=leaf1, Tags=alarm_tags, **_METRIC_ALARM_DEFAULTS)
    ctx.on_cleanup(lambda _n=leaf1: cw.delete_alarms(AlarmNames=[_n]))
    cw.put_metric_alarm(AlarmName=leaf2, Tags=alarm_tags, **_METRIC_ALARM_DEFAULTS)
    ctx.on_cleanup(lambda _n=leaf2: cw.delete_alarms(AlarmNames=[_n]))
    cw.set_alarm_state(AlarmName=leaf1, StateValue="OK", StateReason="forced-OK")
    cw.set_alarm_state(AlarmName=leaf2, StateValue="OK", StateReason="forced-OK")

    composite_name = ctx.unique_name("sim2real-behav-cwprobe-composite-")
    cw.put_composite_alarm(
        AlarmName=composite_name, AlarmRule=f'ALARM("{leaf1}") OR ALARM("{leaf2}")', Tags=alarm_tags
    )
    ctx.on_cleanup(lambda _n=composite_name: cw.delete_alarms(AlarmNames=[_n]))

    def composite_state():
        described = cw.describe_alarms(AlarmNames=[composite_name], AlarmTypes=["CompositeAlarm"]).get(
            "CompositeAlarms", []
        )
        return described[0]["StateValue"] if described else None

    initial = _poll_until(
        composite_state, lambda s: s is not None, timeout_s=60, interval_s=5,
        description="composite alarm reaches a server-evaluated state after creation",
    )
    assert initial == "OK", (
        f"expected the composite to server-evaluate to OK purely from two OK children "
        f"(no SetAlarmState was ever called on the composite), got {initial}"
    )

    # Force ONE child into ALARM -- the composite must auto re-evaluate its
    # AlarmRule and flip to ALARM with NO direct SetAlarmState call on the composite.
    cw.set_alarm_state(AlarmName=leaf1, StateValue="ALARM", StateReason="forced-ALARM")
    flipped = _poll_until(
        composite_state, lambda s: s == "ALARM", timeout_s=60, interval_s=5,
        description="composite alarm auto-flips to ALARM once a child alarm changes state",
    )
    assert flipped == "ALARM", (
        f"expected the composite to auto-flip to ALARM once leaf1 entered ALARM, got {flipped}"
    )

    # Overly-permissive angle: SetAlarmState IS accepted on a composite alarm, but
    # a client-forced value must NOT durably override the server's own derivation
    # -- once a child changes state again, CloudWatch re-derives the composite's
    # real value regardless of what the client most recently forced onto it.
    cw.set_alarm_state(AlarmName=composite_name, StateValue="OK", StateReason="attempted client override")
    cw.set_alarm_state(AlarmName=leaf2, StateValue="ALARM", StateReason="forced-ALARM")
    reverted = _poll_until(
        composite_state, lambda s: s == "ALARM", timeout_s=60, interval_s=5,
        description="composite alarm re-derives ALARM from its children, overriding the forced client SetAlarmState",
    )
    assert reverted == "ALARM", (
        "a client-forced SetAlarmState on a composite alarm must not durably override "
        "server-side evaluation from its children"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
