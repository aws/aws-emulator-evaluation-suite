"""set-alarm-state-invalid-reason-data-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-alarm-state-invalid-reason-data-rejected"
GROUP = "telemetry"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SetAlarmState with a malformed (non-JSON) StateReasonData is rejected with
    InvalidFormat, leaves the alarm's StateValue and alarm history untouched, and a
    subsequent well-formed call against the same alarm still succeeds and is recorded."""
    cw = ctx.client("cloudwatch")
    alarm_name = ctx.unique_name("sim2real-behav-invreason-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace="Sim2RealBehavioral",
        MetricName="InvalidReasonDataProbe",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    baseline_state = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]["StateValue"]
    baseline_history_count = len(
        cw.describe_alarm_history(AlarmName=alarm_name, HistoryItemType="StateUpdate")[
            "AlarmHistoryItems"
        ]
    )

    err = _error(
        lambda: cw.set_alarm_state(
            AlarmName=alarm_name,
            StateValue="ALARM",
            StateReason="malformed reason data",
            StateReasonData="{this is not json",
        )
    )
    assert err["Code"] == "InvalidFormat", f"expected InvalidFormat, got {err!r}"
    expected = ""
    assert err.get("Message", "") == expected, f"expected {expected!r}, got {err.get('Message', '')!r}"

    # Freeze detector: any (incorrect) async side-effect gets three independent chances,
    # spaced out, to land -- and every one of them must still agree with baseline.
    for attempt in range(3):
        time.sleep(1)
        state_after_reject = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0][
            "StateValue"
        ]
        assert state_after_reject == baseline_state, (
            f"alarm state changed to {state_after_reject} despite the rejected SetAlarmState "
            f"call (attempt {attempt + 1}/3)"
        )
        history_after_reject = len(
            cw.describe_alarm_history(AlarmName=alarm_name, HistoryItemType="StateUpdate")[
                "AlarmHistoryItems"
            ]
        )
        assert history_after_reject == baseline_history_count, (
            f"a StateUpdate history item was recorded for a rejected SetAlarmState call "
            f"(attempt {attempt + 1}/3)"
        )

    # Positive control: identical call shape but with well-formed StateReasonData succeeds.
    cw.set_alarm_state(
        AlarmName=alarm_name,
        StateValue="ALARM",
        StateReason="valid reason data",
        StateReasonData=json.dumps({"note": "sim2real behavioral control"}),
    )
    _poll_for_state(cw, alarm_name, "ALARM")
    history_after_control = len(
        cw.describe_alarm_history(AlarmName=alarm_name, HistoryItemType="StateUpdate")[
            "AlarmHistoryItems"
        ]
    )
    assert history_after_control == baseline_history_count + 1, (
        f"expected exactly one new StateUpdate history item, got "
        f"{history_after_control - baseline_history_count}"
    )


def _error(fn):
    """Call fn(); return the botocore Error dict of the ClientError it raises. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected SetAlarmState to be rejected, but it succeeded: {result!r}")


def _poll_for_state(cw, alarm_name: str, expected: str, timeout_s: float = 30.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        state = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]["StateValue"]
        if state == expected:
            return
        time.sleep(2)
    raise AssertionError(f"alarm {alarm_name} never reached state {expected}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
