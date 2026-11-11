"""set-alarm-state-on-missing-alarm-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-alarm-state-on-missing-alarm-rejected"
GROUP = 'overly-permissive'
SERVICES = ['cloudwatch']

def _err(fn):
    """Call fn(); return (Error.Code, Error.Message) of its refusal, raising if fn succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a refusal but the call succeeded: {result!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SetAlarmState on a well-formed alarm name that does not exist fails with ResourceNotFound
    and an empty message and creates no alarm; the same call moves the alarm to ALARM once it
    exists."""
    cw = ctx.client("cloudwatch")
    missing_name = ctx.unique_name("sim2real-behav-cwprobe-alarm-missing-sas-")

    code, message = _err(lambda: cw.set_alarm_state(
        AlarmName=missing_name, StateValue="ALARM", StateReason="probe for missing alarm"
    ))
    assert code == "ResourceNotFound", (
        f"expected ResourceNotFound for a nonexistent AlarmName, got {code}: {message!r}"
    )
    assert message == "", message

    created = cw.describe_alarms(AlarmNames=[missing_name]).get("MetricAlarms", [])
    assert created == [], (
        f"a rejected SetAlarmState call must NEVER implicitly create the alarm, got {created}"
    )

    # Positive control: once an alarm with the identical AlarmName exists, the identical
    # SetAlarmState call must succeed — this is what separates "rejects only the missing
    # case" from "rejects every SetAlarmState call".
    namespace = ctx.unique_name("Sim2Real-CW-")
    cw.put_metric_alarm(
        AlarmName=missing_name,
        Namespace=namespace,
        MetricName="MissingAlarmProbeMetric",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[missing_name]))

    cw.set_alarm_state(AlarmName=missing_name, StateValue="ALARM", StateReason="alarm now exists")
    state = cw.describe_alarms(AlarmNames=[missing_name])["MetricAlarms"][0]["StateValue"]
    assert state == "ALARM", (
        f"expected the identical SetAlarmState call to succeed once the alarm exists, "
        f"got StateValue={state!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
