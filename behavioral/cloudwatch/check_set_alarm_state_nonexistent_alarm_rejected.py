"""set-alarm-state-nonexistent-alarm-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-alarm-state-nonexistent-alarm-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetAlarmState on a nonexistent AlarmName is rejected with ResourceNotFound and creates no alarm resource."""
    cw = ctx.client("cloudwatch")
    ghost_name = ctx.unique_name("sim2real-ghost-alarm-")

    err = _error(
        lambda: cw.set_alarm_state(AlarmName=ghost_name, StateValue="ALARM", StateReason="no such alarm")
    )
    assert err["Code"] == "ResourceNotFound", f"expected ResourceNotFound, got {err!r}"
    expected = ""
    assert err.get("Message", "") == expected, f"expected {expected!r}, got {err.get('Message', '')!r}"

    still_absent = cw.describe_alarms(AlarmNames=[ghost_name])["MetricAlarms"]
    assert still_absent == [], (
        f"a rejected SetAlarmState must not create the alarm as a side effect, got {still_absent}"
    )

    # Positive control: creating the alarm first makes the identical SetAlarmState call succeed.
    namespace = ctx.unique_name("Sim2Real-CW-")
    cw.put_metric_alarm(
        AlarmName=ghost_name,
        Namespace=namespace,
        MetricName="GhostMetric",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        Tags=[{"Key": "team", "Value": "sim2real"}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[ghost_name]))

    cw.set_alarm_state(AlarmName=ghost_name, StateValue="ALARM", StateReason="now exists")
    state = cw.describe_alarms(AlarmNames=[ghost_name])["MetricAlarms"][0]["StateValue"]
    assert state == "ALARM", f"expected ALARM after SetAlarmState on the now-existing alarm, got {state}"


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
