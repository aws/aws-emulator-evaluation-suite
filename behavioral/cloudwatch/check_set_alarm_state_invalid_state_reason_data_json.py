"""set-alarm-state-invalid-state-reason-data-json."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-alarm-state-invalid-state-reason-data-json"
GROUP = 'overly-permissive'
SERVICES = ['cloudwatch']

def _error(fn):
    """Call fn(); return the botocore Error dict of the ClientError it raises. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected SetAlarmState to be rejected, but it succeeded: {result!r}")


def _poll_for_state(cw, alarm_name: str, expected: str, *, timeout_s: float = 30.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]["StateValue"]
        if last == expected:
            return last
        time.sleep(2)
    raise AssertionError(f"alarm {alarm_name} never reached state {expected!r}; last saw {last!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SetAlarmState rejects StateReasonData that is not valid JSON, leaves the alarm's state
    untouched, and an identical call with well-formed StateReasonData still succeeds."""
    cw = ctx.client("cloudwatch")
    alarm_name = ctx.unique_name("sim2real-behav-cwprobe-alarm-")
    namespace = ctx.unique_name("sim2real-behav-cwprobe-ns-")
    ctx.on_cleanup(lambda _n=alarm_name: cw.delete_alarms(AlarmNames=[_n]))

    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=namespace,
        MetricName="Manual",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )

    baseline_state = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]["StateValue"]

    def op():
        return cw.set_alarm_state(
            AlarmName=alarm_name,
            StateValue="ALARM",
            StateReason="bad json",
            StateReasonData="{not valid json",
        )

    err = _error(op)
    assert err["Code"] == "InvalidFormat", f"expected InvalidFormat, got {err!r}"
    expected = ""
    assert err.get("Message", "") == expected, f"expected {expected!r}, got {err.get('Message', '')!r}"

    # Effect-absent: an independent read at the destination must show the rejected call never
    # advanced the alarm's state.
    state_after_reject = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]["StateValue"]
    assert state_after_reject == baseline_state, (
        f"alarm state changed to {state_after_reject!r} despite SetAlarmState being rejected for "
        f"invalid StateReasonData (baseline was {baseline_state!r})"
    )

    # Positive control: the identical call shape with well-formed JSON in StateReasonData
    # succeeds, proving the rejection above was specific to the malformed JSON and not a blanket
    # denial of SetAlarmState against this alarm.
    cw.set_alarm_state(
        AlarmName=alarm_name,
        StateValue="ALARM",
        StateReason="bad json",
        StateReasonData='{"note": "sim2real behavioral control"}',
    )
    terminal_state = _poll_for_state(cw, alarm_name, "ALARM")
    assert terminal_state == "ALARM", f"expected ALARM after well-formed SetAlarmState, got {terminal_state}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
