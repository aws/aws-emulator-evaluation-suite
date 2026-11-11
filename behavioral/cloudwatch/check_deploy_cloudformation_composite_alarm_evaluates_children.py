"""deploy-cloudformation-composite-alarm-evaluates-children."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "deploy-cloudformation-composite-alarm-evaluates-children"
GROUP = "deploy"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed composite alarm with an OR rule over two children enters ALARM when
    either child breaches and leaves ALARM once the breaching child clears."""
    child1_name = ctx.unique_name("sim2real-behav-child1-")
    child2_name = ctx.unique_name("sim2real-behav-child2-")
    composite_name = ctx.unique_name("sim2real-behav-composite-")
    namespace = ctx.unique_name("Sim2RealBehavComposite")

    alarm_rule = f'ALARM("{child1_name}") OR ALARM("{child2_name}")'

    def _child_alarm_props(name: str, metric: str) -> dict[str, Any]:
        return {
            "Type": "AWS::CloudWatch::Alarm",
            "Properties": {
                "AlarmName": name,
                "Namespace": namespace,
                "MetricName": metric,
                "Statistic": "Sum",
                "Period": 60,
                "EvaluationPeriods": 1,
                "Threshold": 1,
                "ComparisonOperator": "GreaterThanThreshold",
                "TreatMissingData": "missing",
            },
        }

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Child1": _child_alarm_props(child1_name, "sim2real-behav-metric-1"),
            "Child2": _child_alarm_props(child2_name, "sim2real-behav-metric-2"),
            "Composite": {
                "Type": "AWS::CloudWatch::CompositeAlarm",
                "DependsOn": ["Child1", "Child2"],
                "Properties": {
                    "AlarmName": composite_name,
                    "AlarmRule": alarm_rule,
                },
            },
        },
    }
    _deploy_cfn(ctx, template)

    cw = ctx.client("cloudwatch")
    described = cw.describe_alarms(AlarmNames=[composite_name], AlarmTypes=["CompositeAlarm"])
    composites = described["CompositeAlarms"]
    assert len(composites) == 1, "CloudFormation did not create the composite alarm"
    assert composites[0]["AlarmRule"] == alarm_rule, (
        f"composite AlarmRule diverged from the deployed template: {composites[0]['AlarmRule']!r} "
        f"!= {alarm_rule!r}"
    )

    def probe() -> str:
        resp = cw.describe_alarms(AlarmNames=[composite_name], AlarmTypes=["CompositeAlarm"])
        return resp["CompositeAlarms"][0]["StateValue"]

    # Baseline: with neither child in ALARM, the composite must not already read ALARM --
    # otherwise a target that always reports ALARM regardless of its children would pass below.
    baseline_state = probe()
    assert baseline_state != "ALARM", (
        f"composite alarm read ALARM before either child breached (got {baseline_state!r}); "
        "the derivation below would prove nothing"
    )

    # Force child1 into ALARM; the OR rule must derive composite ALARM from it alone.
    cw.set_alarm_state(
        AlarmName=child1_name,
        StateValue="ALARM",
        StateReason="sim2real behavioral check forced child1 breach",
    )
    state = _poll_until(probe, lambda s: s == "ALARM", timeout_s=120.0, interval_s=5.0)
    assert state == "ALARM", f"composite did not derive ALARM from child1 (last state: {state!r})"

    # Clear child1 back to OK; the composite must leave ALARM, proving live re-evaluation
    # rather than a one-shot fluke that stuck on the first breach.
    cw.set_alarm_state(
        AlarmName=child1_name,
        StateValue="OK",
        StateReason="sim2real behavioral check cleared child1 breach",
    )
    state = _poll_until(probe, lambda s: s != "ALARM", timeout_s=120.0, interval_s=5.0)
    assert state != "ALARM", f"composite stayed ALARM after child1 cleared (last state: {state!r})"

    # The OR rule must derive ALARM from child2 too, not just the first referenced child.
    cw.set_alarm_state(
        AlarmName=child2_name,
        StateValue="ALARM",
        StateReason="sim2real behavioral check forced child2 breach",
    )
    state = _poll_until(probe, lambda s: s == "ALARM", timeout_s=120.0, interval_s=5.0)
    assert state == "ALARM", f"composite did not derive ALARM from child2 (last state: {state!r})"


def _deploy_cfn(ctx: Any, template: dict[str, Any]) -> str:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-stack-")
    cfn.create_stack(StackName=stack_name, TemplateBody=json.dumps(template))
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_name))
    waiter = cfn.get_waiter("stack_create_complete")
    try:
        waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    except Exception as exc:  # surface the real CFN failure reason
        events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
        reasons = [
            f"{e.get('LogicalResourceId')}: {e.get('ResourceStatus')} - {e.get('ResourceStatusReason')}"
            for e in events
            if e.get("ResourceStatusReason")
        ]
        raise AssertionError(f"stack {stack_name} failed to create: {reasons}") from exc
    return stack_name


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 60.0,
    interval_s: float = 2.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last: Any = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
