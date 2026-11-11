"""set-alarm-state-invalid-json-reason-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-alarm-state-invalid-json-reason-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SetAlarmState must reject a StateReasonData payload that is not syntactically
    valid JSON with InvalidFormat, rather than accepting it as an opaque string."""
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name("sim2real-alarm-")
    namespace = ctx.unique_name("Sim2RealBehavioral-")

    cw.put_metric_alarm(
        AlarmName=name,
        Namespace=namespace,
        MetricName="InvocationCount",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[name]))

    # Positive control: a well-formed StateReasonData is accepted and the transition
    # takes effect, so the account and this alarm's wiring are known-good before we
    # break the one thing under test.
    cw.set_alarm_state(
        AlarmName=name,
        StateValue="OK",
        StateReason="control call with well-formed reason data",
        StateReasonData=json.dumps({"note": "sim2real behavioral control"}),
    )
    control_state = cw.describe_alarms(AlarmNames=[name])["MetricAlarms"][0]["StateValue"]
    assert control_state == "OK", f"positive control call did not take effect, got {control_state}"

    # Break exactly one thing: StateReasonData is no longer valid JSON. The attempted
    # transition targets a different state (ALARM) than the control left the alarm in
    # (OK), so an independent read distinguishes "rejected" from "silently accepted".
    err = _error(
        lambda: cw.set_alarm_state(
            AlarmName=name,
            StateValue="ALARM",
            StateReason="bad json test",
            StateReasonData="{this is not valid json",
        )
    )
    assert err["Code"] == "InvalidFormat", f"expected InvalidFormat, got {err!r}"
    expected = ""
    assert err.get("Message", "") == expected, f"expected {expected!r}, got {err.get('Message', '')!r}"

    # And the alarm must remain in the control's state, untouched by the rejected call.
    state = cw.describe_alarms(AlarmNames=[name])["MetricAlarms"][0]["StateValue"]
    assert state == "OK", f"rejected SetAlarmState call should not have changed state, got {state}"


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
