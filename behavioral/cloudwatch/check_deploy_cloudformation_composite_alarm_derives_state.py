"""deploy-cloudformation-composite-alarm-derives-state."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags


CHECK = "deploy-cloudformation-composite-alarm-derives-state"
GROUP = "deploy"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A composite alarm and its child metric alarm deployed together via one CFN stack
    correctly derive the composite's state when the child alarm's state is set, proving
    the AlarmRule wiring is functionally evaluated -- not just that the stack succeeded."""
    cfn = ctx.client("cloudformation")
    cw = ctx.client("cloudwatch")

    stack_name = ctx.unique_name("sim2real-cfn-composite-")
    child_name = ctx.unique_name("sim2real-child-alarm-")
    composite_name = ctx.unique_name("sim2real-composite-alarm-")

    template = json.dumps(
        {
            "Parameters": {
                "ChildAlarmName": {"Type": "String"},
                "CompositeAlarmName": {"Type": "String"},
            },
            "Resources": {
                "ChildAlarm": {
                    "Type": "AWS::CloudWatch::Alarm",
                    "Properties": {
                        "AlarmName": {"Ref": "ChildAlarmName"},
                        "Namespace": "Sim2RealCompositeTest",
                        "MetricName": "DummyMetric",
                        "Statistic": "Maximum",
                        "Period": 60,
                        "EvaluationPeriods": 1,
                        "Threshold": 100,
                        "ComparisonOperator": "GreaterThanThreshold",
                        "TreatMissingData": "notBreaching",
                    },
                },
                "CompositeAlarm": {
                    "Type": "AWS::CloudWatch::CompositeAlarm",
                    "Properties": {
                        "AlarmName": {"Ref": "CompositeAlarmName"},
                        "AlarmRule": {"Fn::Sub": 'ALARM("${ChildAlarmName}")'},
                    },
                    "DependsOn": "ChildAlarm",
                },
            },
        }
    )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template,
        Parameters=[
            {"ParameterKey": "ChildAlarmName", "ParameterValue": child_name},
            {"ParameterKey": "CompositeAlarmName", "ParameterValue": composite_name},
        ],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))

    _wait_for_stack_status(ctx, stack_name, {"CREATE_COMPLETE"}, timeout_s=240)

    # Both alarms must actually exist as distinct resources per the stack.
    # AlarmTypes defaults to MetricAlarm only -- composite alarms are omitted unless
    # explicitly requested, so ask for both types explicitly.
    described = cw.describe_alarms(
        AlarmNames=[child_name, composite_name],
        AlarmTypes=["MetricAlarm", "CompositeAlarm"],
    )
    assert len(described["MetricAlarms"]) == 1, f"expected 1 metric alarm, got {described['MetricAlarms']!r}"
    assert len(described["CompositeAlarms"]) == 1, f"expected 1 composite alarm, got {described['CompositeAlarms']!r}"
    assert described["CompositeAlarms"][0]["AlarmRule"] == f'ALARM("{child_name}")', (
        f"expected AlarmRule ALARM(\"{child_name}\"), got {described['CompositeAlarms'][0]['AlarmRule']!r}"
    )

    # Force the child alarm into ALARM and verify the composite derives ALARM too.
    cw.set_alarm_state(
        AlarmName=child_name,
        StateValue="ALARM",
        StateReason="sim2real forcing child breach",
        StateReasonData=json.dumps({"forced": True}),
    )
    composite_state = _poll_composite_state(ctx, composite_name, "ALARM", timeout_s=120)
    assert composite_state == "ALARM", (
        f"composite alarm did not derive ALARM from its child, last state was {composite_state}"
    )

    # Flip the child back to OK and verify the composite derives OK, proving the
    # relationship is live re-evaluation, not a one-shot fluke on stack creation.
    cw.set_alarm_state(
        AlarmName=child_name,
        StateValue="OK",
        StateReason="sim2real clearing child breach",
        StateReasonData=json.dumps({"forced": True}),
    )
    composite_state = _poll_composite_state(ctx, composite_name, "OK", timeout_s=120)
    assert composite_state == "OK", (
        f"composite alarm did not derive OK after child cleared, last state was {composite_state}"
    )

    # Run the teardown now (idempotent with the on_cleanup fallback) and prove it
    # took effect at an independent read, rather than leaving the delete unasserted.
    _delete_stack(ctx, stack_name)
    after_delete = cw.describe_alarms(
        AlarmNames=[child_name, composite_name],
        AlarmTypes=["MetricAlarm", "CompositeAlarm"],
    )
    assert after_delete["MetricAlarms"] == [], (
        f"child alarm {child_name} still exists after stack delete: {after_delete['MetricAlarms']!r}"
    )
    assert after_delete["CompositeAlarms"] == [], (
        f"composite alarm {composite_name} still exists after stack delete: {after_delete['CompositeAlarms']!r}"
    )


# ===== helpers =====
def _wait_for_stack_status(ctx, stack_name: str, ok_statuses: set[str], timeout_s: float) -> None:
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        assert stacks, f"stack {stack_name} disappeared"
        last_status = stacks[0]["StackStatus"]
        if last_status in ok_statuses:
            return
        if last_status.endswith("FAILED") or last_status == "ROLLBACK_COMPLETE":
            raise AssertionError(f"stack {stack_name} reached {last_status}")
        time.sleep(5)
    raise AssertionError(f"stack {stack_name} never reached {ok_statuses}, last was {last_status}")


def _delete_stack(ctx, stack_name: str, timeout_s: float = 240.0) -> None:
    """Delete the stack and wait for it to vanish; DELETE_FAILED or the deadline raises."""
    from botocore.exceptions import ClientError

    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        try:
            stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == "ValidationError" and "does not exist" in err.get("Message", ""):
                return
            raise
        status = stacks[0]["StackStatus"] if stacks else "DELETE_COMPLETE"
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_name} reached DELETE_FAILED")
        time.sleep(2)
    raise AssertionError(f"stack {stack_name} not deleted within {timeout_s}s (last status {status})")


def _poll_composite_state(ctx, composite_name: str, target_state: str, timeout_s: float) -> str | None:
    cw = ctx.client("cloudwatch")
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        alarms = cw.describe_alarms(
            AlarmNames=[composite_name], AlarmTypes=["CompositeAlarm"]
        )["CompositeAlarms"]
        if alarms:
            last_state = alarms[0]["StateValue"]
            if last_state == target_state:
                return last_state
        time.sleep(5)
    return last_state


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
