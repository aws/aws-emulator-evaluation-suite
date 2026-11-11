"""alarm-state-transitioned-vs-updated-timestamp."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "alarm-state-transitioned-vs-updated-timestamp"
GROUP = 'alarms'
SERVICES = ['cloudwatch']


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _assert_stays(probe, predicate, *, hold_s, interval_s, description):
    """Assert predicate(probe()) holds continuously for hold_s (bounded negative)."""
    deadline = time.monotonic() + hold_s
    while True:
        val = probe()
        assert predicate(val), f"{description} -- observed {val!r}"
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)


def _swallow(fn):
    """Run a cleanup callable; an alarm that is already gone (ResourceNotFound) is not an error."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Through INSUFFICIENT_DATA -> OK -> OK -> ALARM -> ALARM -> OK via SetAlarmState,
    StateTransitionedTimestamp advances only on a state change, StateUpdatedTimestamp is never
    earlier than it, and DescribeAlarmHistory holds the three transitions and no self-transition."""
    cw = ctx.client("cloudwatch")
    alarm = ctx.unique_name("sim2real-behav-cwprobe-alarm-transitions-")
    ns = ctx.unique_name("sim2real-behav-cwprobe-ns-transitions-")

    cw.put_metric_alarm(
        AlarmName=alarm,
        Namespace=ns,
        MetricName="NeverPublished",
        Statistic="Sum",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="ignore",
        ActionsEnabled=False,
        Tags=[{"Key": "team", "Value": "sim2real"}],
    )
    ctx.on_cleanup(lambda: _swallow(lambda: cw.delete_alarms(AlarmNames=[alarm])))

    def describe():
        alarms = cw.describe_alarms(AlarmNames=[alarm], AlarmTypes=["MetricAlarm"])["MetricAlarms"]
        assert len(alarms) == 1, f"expected exactly one alarm named {alarm}, got {alarms}"
        return alarms[0]

    def set_state(value, reason):
        cw.set_alarm_state(AlarmName=alarm, StateValue=value, StateReason=reason)

    def wait_for_state(value):
        return _poll_until(
            describe,
            lambda a: a["StateValue"] == value,
            timeout_s=60,
            interval_s=2,
            description=f"alarm {alarm} to report StateValue={value}",
        )

    initial = describe()
    assert initial["StateValue"] == "INSUFFICIENT_DATA", (
        f"a freshly created alarm starts in INSUFFICIENT_DATA, got {initial['StateValue']}"
    )

    # --- Transition 1: INSUFFICIENT_DATA -> OK (a real change) ---
    set_state("OK", "probe: first real transition")
    a_ok = wait_for_state("OK")
    trans_1 = a_ok["StateTransitionedTimestamp"]
    assert a_ok["StateUpdatedTimestamp"] >= trans_1, (
        f"StateUpdatedTimestamp ({a_ok['StateUpdatedTimestamp']}) must never precede "
        f"StateTransitionedTimestamp ({trans_1})"
    )

    # --- Repeat the SAME state: this is NOT a transition ---
    set_state("OK", "probe: same-state repeat, must not count as a transition")
    held = _assert_stays(
        lambda: describe(),
        lambda a: a["StateValue"] == "OK" and a["StateTransitionedTimestamp"] == trans_1,
        hold_s=20,
        interval_s=4,
        description=(
            "re-asserting the state the alarm is already in must leave "
            "StateTransitionedTimestamp exactly where it was"
        ),
    )
    assert held["StateUpdatedTimestamp"] >= held["StateTransitionedTimestamp"], (
        f"the StateUpdated >= StateTransitioned invariant must hold after a same-state write, got {held}"
    )

    # --- Transition 2: OK -> ALARM (a real change; the timestamp must advance) ---
    set_state("ALARM", "probe: second real transition")
    a_alarm = _poll_until(
        describe,
        lambda a: a["StateValue"] == "ALARM" and a["StateTransitionedTimestamp"] > trans_1,
        timeout_s=60,
        interval_s=2,
        description="alarm to reach ALARM with an advanced StateTransitionedTimestamp",
    )
    trans_2 = a_alarm["StateTransitionedTimestamp"]
    assert trans_2 > trans_1, (
        f"a real OK->ALARM change must advance StateTransitionedTimestamp past {trans_1}, got {trans_2}"
    )
    assert a_alarm["StateReason"] == "probe: second real transition", (
        f"the caller-supplied StateReason must be stored verbatim, got {a_alarm.get('StateReason')!r}"
    )

    # --- Repeat ALARM: again not a transition ---
    set_state("ALARM", "probe: second same-state repeat")
    _assert_stays(
        lambda: describe()["StateTransitionedTimestamp"],
        lambda ts: ts == trans_2,
        hold_s=20,
        interval_s=4,
        description="a repeated ALARM write must not advance StateTransitionedTimestamp",
    )

    # --- Transition 3: ALARM -> OK ---
    set_state("OK", "probe: third real transition")
    a_back = _poll_until(
        describe,
        lambda a: a["StateValue"] == "OK" and a["StateTransitionedTimestamp"] > trans_2,
        timeout_s=60,
        interval_s=2,
        description="alarm to return to OK with an advanced StateTransitionedTimestamp",
    )
    assert a_back["StateTransitionedTimestamp"] > trans_2, (
        f"ALARM->OK must advance StateTransitionedTimestamp past {trans_2}, "
        f"got {a_back['StateTransitionedTimestamp']}"
    )

    # --- History: three real transitions, zero self-transitions ---
    def state_updates():
        items = cw.describe_alarm_history(
            AlarmName=alarm,
            HistoryItemType="StateUpdate",
            ScanBy="TimestampAscending",
        )["AlarmHistoryItems"]
        out = []
        for item in items:
            data = json.loads(item["HistoryData"])
            out.append(
                (
                    data["oldState"]["stateValue"],
                    data["newState"]["stateValue"],
                    item["Timestamp"],
                )
            )
        return out

    updates = _poll_until(
        state_updates,
        lambda u: len(u) >= 3,
        timeout_s=90,
        interval_s=5,
        description="all three state transitions to appear in the alarm history",
    )
    self_transitions = [(o, n) for o, n, _ in updates if o == n]
    assert self_transitions == [], (
        f"the alarm history must never record a self-transition: a SetAlarmState call that does not "
        f"change the state is not a StateUpdate event; got {self_transitions}"
    )
    pairs = [(o, n) for o, n, _ in updates]
    expected = [("INSUFFICIENT_DATA", "OK"), ("OK", "ALARM"), ("ALARM", "OK")]
    idx = 0
    for pair in pairs:
        if idx < len(expected) and pair == expected[idx]:
            idx += 1
    assert idx == len(expected), (
        f"the three real transitions {expected} must appear in the history in that order (each "
        f"item's oldState must equal the previous newState); got {pairs}"
    )
    stamps = [ts for _, _, ts in updates]
    assert stamps == sorted(stamps), (
        f"ScanBy=TimestampAscending must return the history oldest-first, got {stamps}"
    )

    # --- Control: the alarm is still readable and consistent ---
    control = describe()
    assert control["StateValue"] == "OK", f"the alarm must still be OK, got {control['StateValue']}"
    assert control["StateUpdatedTimestamp"] >= control["StateTransitionedTimestamp"], (
        f"the StateUpdated >= StateTransitioned invariant must hold at the end, got {control}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
