"""set-alarm-state-invalid-format-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-alarm-state-invalid-format-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SetAlarmState with StateReasonData that is not valid JSON fails with InvalidFormat and its
    exact message and leaves the alarm OK, while the same call with valid JSON moves it to ALARM."""
    cw = ctx.client("cloudwatch")
    alarm_name = ctx.unique_name("sim2real-behav-badformat-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace="AWS/EC2",
        MetricName="CPUUtilization",
        Statistic="Average",
        Period=300,
        EvaluationPeriods=1,
        Threshold=90.0,
        ComparisonOperator="GreaterThanThreshold",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    # Positive control: SetAlarmState works on this alarm at all, and establishes a
    # known baseline state before we probe the rejection path.
    cw.set_alarm_state(AlarmName=alarm_name, StateValue="OK", StateReason="baseline")
    baseline = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]["StateValue"]
    assert baseline == "OK", f"positive control failed to set alarm to OK, got {baseline}"

    err = _error(
        lambda: cw.set_alarm_state(
            AlarmName=alarm_name,
            StateValue="ALARM",
            StateReason="forced for behavioral fidelity check",
            StateReasonData="{this is not valid json",
        )
    )
    # Malformed JSON in StateReasonData is rejected as a format error
    # (InvalidFormatFault / error code "InvalidFormat"), not a generic
    # InvalidParameterValue.
    assert err["Code"] == "InvalidFormat", f"expected InvalidFormat, got {err!r}"
    expected = ""
    assert err.get("Message", "") == expected, f"expected {expected!r}, got {err.get('Message', '')!r}"

    # The alarm's state must be unaffected by the rejected call: it must still read
    # exactly the state the positive control set, not merely "not ALARM".
    described = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]
    assert described["StateValue"] == "OK", (
        f"alarm state changed to {described['StateValue']} despite SetAlarmState "
        "being rejected for invalid StateReasonData"
    )

    # Restore leg: the identical call shape with well-formed JSON in StateReasonData
    # still succeeds, so the rejection above is specific to the malformed payload.
    cw.set_alarm_state(
        AlarmName=alarm_name,
        StateValue="ALARM",
        StateReason="forced for behavioral fidelity check",
        StateReasonData='{"note": "well-formed control"}',
    )
    restored = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]["StateValue"]
    assert restored == "ALARM", f"well-formed SetAlarmState call did not succeed, got {restored}"


def _error(fn):
    """Call fn(); return the botocore Error dict of the ClientError it raises. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected SetAlarmState to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
