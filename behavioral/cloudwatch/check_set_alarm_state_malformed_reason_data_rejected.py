"""set-alarm-state-malformed-reason-data-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-alarm-state-malformed-reason-data-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SetAlarmState rejects a StateReasonData value that is not valid JSON, leaves the
    alarm's state untouched, and an otherwise-identical call with well-formed
    StateReasonData still succeeds."""
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name("sim2real-cw-alarm-")
    cw.put_metric_alarm(
        AlarmName=name,
        Namespace=ctx.unique_name("sim2real-cw-ns-"),
        MetricName="DummyMetric",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[name]))

    # Positive control: a well-formed call establishes a known baseline state, proving
    # the account/credentials/alarm are otherwise healthy before the negative is tried.
    cw.set_alarm_state(AlarmName=name, StateValue="OK", StateReason="baseline")
    baseline = cw.describe_alarms(AlarmNames=[name])["MetricAlarms"][0]["StateValue"]
    assert baseline == "OK", f"expected baseline state OK, got {baseline}"

    err = _error(
        lambda: cw.set_alarm_state(
            AlarmName=name,
            StateValue="ALARM",
            StateReason="test",
            StateReasonData="{not valid json",
        )
    )
    assert err["Code"] == "InvalidFormat", f"expected InvalidFormat, got {err!r}"
    expected = ""
    assert err.get("Message", "") == expected, f"expected {expected!r}, got {err.get('Message', '')!r}"

    # Effect absent: the rejected call must not have moved the alarm off baseline.
    after_reject = cw.describe_alarms(AlarmNames=[name])["MetricAlarms"][0]["StateValue"]
    assert after_reject == "OK", (
        f"rejected SetAlarmState call must not change state, saw {after_reject}"
    )

    # The identical call shape with well-formed StateReasonData still succeeds, so the
    # rejection above is specific to the malformed field, not a broken alarm/permissions.
    cw.set_alarm_state(
        AlarmName=name,
        StateValue="ALARM",
        StateReason="test",
        StateReasonData='{"valid": "json"}',
    )
    after_control = cw.describe_alarms(AlarmNames=[name])["MetricAlarms"][0]["StateValue"]
    assert after_control == "ALARM", (
        f"well-formed SetAlarmState call should have succeeded, saw {after_control}"
    )


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
