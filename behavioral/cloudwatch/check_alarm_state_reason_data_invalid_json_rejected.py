"""alarm-state-reason-data-invalid-json-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "alarm-state-reason-data-invalid-json-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SetAlarmState must reject a StateReasonData payload that is not valid JSON with
    InvalidFormat and leave the alarm's state unchanged, while a call of the same shape
    carrying syntactically valid JSON is accepted."""
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name("sim2real-behav-alarm-")
    cw.put_metric_alarm(
        AlarmName=name,
        MetricName="Sim2RealMetric",
        Namespace="Sim2RealBehavioral",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        ActionsEnabled=False,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[name]))

    cw.set_alarm_state(AlarmName=name, StateValue="OK", StateReason="baseline")
    before = cw.describe_alarms(AlarmNames=[name])["MetricAlarms"][0]["StateValue"]
    assert before == "OK", f"expected fresh alarm forced to OK, got {before}"

    # Positive control: the same call shape but with syntactically valid JSON in
    # StateReasonData is accepted. Without this, a target that rejects every non-empty
    # StateReasonData -- regardless of whether it parses as JSON -- would pass the
    # negative below for the wrong reason.
    cw.set_alarm_state(
        AlarmName=name,
        StateValue="ALARM",
        StateReason="valid-json-control",
        StateReasonData=json.dumps({"probe": "sim2real-behavioral-control"}),
    )
    control = _poll_for_state(cw, name, "ALARM")
    assert control == "ALARM", (
        f"valid-JSON StateReasonData call should have reached ALARM, saw {control}"
    )

    code, message = _error(
        lambda: cw.set_alarm_state(
            AlarmName=name,
            StateValue="OK",
            StateReason="bad-json-attempt",
            StateReasonData="{this is not json",
        )
    )
    # Real CloudWatch surfaces this as the short-form "InvalidFormat" code (not the
    # "InvalidFormatFault" shape name the API docs imply).
    assert code == "InvalidFormat", f"expected InvalidFormat, got {code}"
    expected = ""  # real AWS returns an empty message for this code
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    after = cw.describe_alarms(AlarmNames=[name])["MetricAlarms"][0]["StateValue"]
    assert after == control, (
        f"rejected SetAlarmState call must not change state, saw {after}, expected {control}"
    )


def _error(fn):
    """(code, message) of the ClientError fn() raises. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _poll_for_state(cw, alarm_name: str, expected: str, timeout_s: float = 30.0):
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]["StateValue"]
        if state == expected:
            return state
        time.sleep(2)
    raise AssertionError(f"alarm {alarm_name} never reached state {expected}, last saw {state}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
