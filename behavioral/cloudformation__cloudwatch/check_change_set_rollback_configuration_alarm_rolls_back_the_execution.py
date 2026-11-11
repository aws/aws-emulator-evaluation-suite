"""change-set-rollback-configuration-alarm-rolls-back-the-execution."""
from __future__ import annotations

import json
import time


from behavioral_harness import tags

CHECK = "change-set-rollback-configuration-alarm-rolls-back-the-execution"
GROUP = "change_sets"
SERVICES = ["cloudformation", "cloudwatch"]

_TAGS = [{"Key": "sim2real", "Value": CHECK}]


def _template(*handles):
    return json.dumps({"Resources": {h: {"Type": "AWS::CloudFormation::WaitConditionHandle"}
                                     for h in handles}})


def _delete_alarm(cw, name):
    cw.delete_alarms(AlarmNames=[name])
    left = cw.describe_alarms(AlarmNames=[name])["MetricAlarms"]
    if left:
        raise RuntimeError(f"alarm {name} still exists after delete")


def _cap(ctx, own_s, margin_s=15.0):
    """Bound a wait by the check's remaining budget."""
    left = ctx.time_left()
    return own_s if left is None else max(1.0, min(own_s, left - margin_s))


def _wait_stack(cf, stack_id, *, timeout_s=300.0):
    """Poll DescribeStacks by id until the status leaves *_IN_PROGRESS; return the stack."""
    deadline = time.monotonic() + timeout_s
    while True:
        stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() > deadline:
            raise AssertionError(f"stack still {stack['StackStatus']!r} after {timeout_s}s")
        time.sleep(3)


def _wait_change_set(cf, cs_id, *, timeout_s=180.0, **extra):
    """Poll DescribeChangeSet until CREATE_COMPLETE or FAILED; return the description."""
    deadline = time.monotonic() + timeout_s
    while True:
        cs = cf.describe_change_set(ChangeSetName=cs_id, **extra)
        if cs["Status"] in ("CREATE_COMPLETE", "FAILED"):
            return cs
        if time.monotonic() > deadline:
            raise AssertionError(f"change set still {cs['Status']!r} after {timeout_s}s")
        time.sleep(3)


def _delete_stack(cf, stack_id, *, timeout_s=600.0):
    """Delete a stack by id and poll until DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    cf.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    while True:
        stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
        if stack["StackStatus"] in ("DELETE_COMPLETE", "DELETE_FAILED"):
            break
        if time.monotonic() > deadline:
            raise RuntimeError(f"stack {stack_id} still {stack['StackStatus']!r} after {timeout_s}s")
        time.sleep(3)
    if stack["StackStatus"] != "DELETE_COMPLETE":
        raise RuntimeError(f"stack {stack_id} ended {stack['StackStatus']!r}: "
                           f"{stack.get('StackStatusReason')!r}")


def _events(cf, stack_id):
    """Every StackEvent of the stack, oldest first."""
    out = []
    for page in cf.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        out.extend(page["StackEvents"])
    return out[::-1]


def _execute(ctx, cf, stack_id, handles, rollback):
    cs_id = cf.create_change_set(StackName=stack_id, ChangeSetType="UPDATE",
                                 TemplateBody=_template(*handles), RollbackConfiguration=rollback,
                                 ChangeSetName=ctx.unique_name("sim2real-xsvc-csrbcfg-cs-"))["Id"]
    cs = _wait_change_set(cf, cs_id, timeout_s=_cap(ctx, 180.0))
    assert cs["Status"] == "CREATE_COMPLETE", f"change set: {cs.get('StatusReason')!r}"
    before = {e["EventId"] for e in _events(cf, stack_id)}
    cf.execute_change_set(ChangeSetName=cs_id)
    return cs, _wait_stack(cf, stack_id, timeout_s=_cap(ctx, 420.0)), before


@tags("axis:happy-path", "cap:c3", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A change set's RollbackConfiguration is echoed and, with its trigger alarm in ALARM, rolls the
    execution back to UPDATE_ROLLBACK_COMPLETE with the exact reason; without triggers it completes.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-rollback-triggers.html
    """
    cf = ctx.client("cloudformation")
    cw = ctx.client("cloudwatch")
    alarm = ctx.unique_name("sim2real-xsvc-csrbcfg-")
    cw.put_metric_alarm(AlarmName=alarm, Namespace="sim2real/xsvc", MetricName=alarm,
                        Statistic="Sum", Period=60, EvaluationPeriods=1, Threshold=1.0,
                        ComparisonOperator="GreaterThanOrEqualToThreshold",
                        TreatMissingData="breaching", Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_alarm(cw, alarm))
    alarm_arn = cw.describe_alarms(AlarmNames=[alarm])["MetricAlarms"][0]["AlarmArn"]
    cw.set_alarm_state(AlarmName=alarm, StateValue="ALARM", StateReason="arm the rollback trigger")

    stack_id = cf.create_stack(StackName=ctx.unique_name("sim2real-xsvc-csrbcfg-"), Tags=_TAGS,
                               TemplateBody=_template("One"))["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, stack_id))
    status = _wait_stack(cf, stack_id, timeout_s=_cap(ctx, 300.0))["StackStatus"]
    assert status == "CREATE_COMPLETE", f"setup stack ended {status!r}, expected CREATE_COMPLETE"
    state = cw.describe_alarms(AlarmNames=[alarm])["MetricAlarms"][0]["StateValue"]
    assert state == "ALARM", f"the trigger alarm must be in ALARM before the execution: {state!r}"

    rollback = {"RollbackTriggers": [{"Arn": alarm_arn, "Type": "AWS::CloudWatch::Alarm"}],
                "MonitoringTimeInMinutes": 1}
    cs, stack, before = _execute(ctx, cf, stack_id, ("One", "Two"), rollback)
    assert cs.get("RollbackConfiguration") == rollback, cs.get("RollbackConfiguration")
    assert stack["StackStatus"] == "UPDATE_ROLLBACK_COMPLETE", (
        f"the ALARM trigger must roll the execution back, got {stack['StackStatus']!r}")
    new = [e for e in _events(cf, stack_id) if e["EventId"] not in before]
    rolling = [e.get("ResourceStatusReason") for e in new
               if e["ResourceStatus"] == "UPDATE_ROLLBACK_IN_PROGRESS"]
    assert rolling == [f"The following CloudWatch Alarms were in ALARM state: {alarm}"], rolling
    two_events = [(e["LogicalResourceId"], e["ResourceStatus"]) for e in new
                  if e["LogicalResourceId"] == "Two"]
    assert two_events == [], (
        f"an alarm already in ALARM aborts before the added Two is ever touched: {two_events!r}")
    names = {r["LogicalResourceId"]
             for r in cf.list_stack_resources(StackName=stack_id)["StackResourceSummaries"]}
    assert names == {"One"}, f"rolled-back stack resources: {sorted(names)!r}"

    # Control: the same update with no triggers completes while the alarm is still in ALARM.
    _, stack, _ = _execute(ctx, cf, stack_id, ("One", "Two"),
                           {"RollbackTriggers": [], "MonitoringTimeInMinutes": 0})
    assert stack["StackStatus"] == "UPDATE_COMPLETE", f"control: {stack['StackStatus']!r}"
    control_names = {r["LogicalResourceId"]
                     for r in cf.list_stack_resources(StackName=stack_id)["StackResourceSummaries"]}
    assert control_names == {"One", "Two"}, (
        f"control: without a trigger, Two must actually be added: {sorted(control_names)!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
