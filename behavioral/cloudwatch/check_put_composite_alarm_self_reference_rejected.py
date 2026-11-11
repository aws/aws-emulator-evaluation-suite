"""put-composite-alarm-self-reference-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-composite-alarm-self-reference-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutCompositeAlarm whose AlarmRule names the composite itself is rejected with ValidationError and
    the exact "alarms [<own ARN>] in the alarm rule do not exist" message, creating nothing, while a
    composite referencing an existing metric alarm is created with that AlarmRule."""
    cw = ctx.client("cloudwatch")

    self_ref_name = ctx.unique_name("sim2real-composite-selfref-")
    self_rule = f'ALARM("{self_ref_name}")'
    code = None
    message = ""
    try:
        cw.put_composite_alarm(AlarmName=self_ref_name, AlarmRule=self_rule)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message2 = exc.response["Error"]["Message"]
        message = exc.response["Error"].get("Message", "")
    assert code == "ValidationError", f"expected ValidationError, got {code!r}"
    assert message2 == f"Could not save the composite alarm as alarms [arn:aws:cloudwatch:{ctx.region}:{ctx.account}:alarm:{self_ref_name}] in the alarm rule do not exist", (
        f"expected the exact ValidationError message AWS returns, got {message2!r}"
    )
    assert self_ref_name in message, f"expected the self-referenced alarm name in the error, got: {message!r}"

    # Effect absent: the rejected self-referencing composite alarm must not exist.
    resp = cw.describe_alarms(AlarmNames=[self_ref_name], AlarmTypes=["CompositeAlarm"])
    assert resp["CompositeAlarms"] == [], resp["CompositeAlarms"]

    # Positive control: a normal metric alarm plus a composite alarm that
    # references it (a real, pre-existing alarm, no cycle) is accepted.
    metric_alarm_name = ctx.unique_name("sim2real-composite-metric-")
    cw.put_metric_alarm(
        AlarmName=metric_alarm_name,
        Namespace="AWS/EC2",
        MetricName="CPUUtilization",
        Statistic="Average",
        Period=300,
        EvaluationPeriods=1,
        Threshold=90.0,
        ComparisonOperator="GreaterThanThreshold",
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[metric_alarm_name]))
    control_name = ctx.unique_name("sim2real-composite-control-")
    cw.put_composite_alarm(
        AlarmName=control_name, AlarmRule=f'ALARM("{metric_alarm_name}")'
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[control_name]))

    # The control is read back through DescribeAlarms, polled briefly because a new alarm
    # may not be visible at once; no evaluation cycle is awaited.
    control_alarms = _poll_until_visible(cw, control_name)
    assert len(control_alarms) == 1, control_alarms
    assert control_alarms[0]["AlarmRule"] == f'ALARM("{metric_alarm_name}")', control_alarms[0]


def _poll_until_visible(cw, alarm_name, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    alarms = []
    while time.monotonic() < deadline:
        alarms = cw.describe_alarms(AlarmNames=[alarm_name], AlarmTypes=["CompositeAlarm"])["CompositeAlarms"]
        if alarms:
            return alarms
        time.sleep(interval_s)
    raise AssertionError(f"{alarm_name} did not become visible within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
