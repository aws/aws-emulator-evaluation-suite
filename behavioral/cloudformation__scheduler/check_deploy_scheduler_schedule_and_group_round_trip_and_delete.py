"""deploy-scheduler-schedule-and-group-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-scheduler-schedule-and-group-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "scheduler"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in ("DELETE_IN_PROGRESS",
                                                          "REVIEW_IN_PROGRESS"):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"},
                        deadline - time.monotonic())
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [i for i, e in enumerate(events) if e.get("PhysicalResourceId") == stack_id
                  and e["ResourceStatus"] == "DELETE_IN_PROGRESS"]
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                  for e in events[starts[-1] if starts else 0:]
                  if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


# ---- Check-specific: the template, then run(). ----

_SCHEDULE_EXPRESSION = "at(2099-12-31T23:59:59)"


def _template(group_name, queue_name, role_name, schedule_name, schedule_input):
    # The Schedule is a sibling of the ScheduleGroup, not nested in it: CloudFormation's own
    # Fn::GetAtt resolution for a Scheduler Schedule's Arn 404s when the schedule belongs to a
    # non-default group, even though a direct GetSchedule call succeeds immediately -- a real
    # AWS resource-handler gap, not a timing issue. Each type is proven independently instead.
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Group": {
                "Type": "AWS::Scheduler::ScheduleGroup",
                "Properties": {"Name": group_name},
            },
            "Queue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {"QueueName": queue_name},
            },
            "SchedulerRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": role_name,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "scheduler.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }],
                    },
                    "Policies": [{
                        "PolicyName": "AllowSendToQueue",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Action": "sqs:SendMessage",
                                "Resource": {"Fn::GetAtt": ["Queue", "Arn"]},
                            }],
                        },
                    }],
                },
            },
            "Schedule": {
                "Type": "AWS::Scheduler::Schedule",
                "Properties": {
                    "Name": schedule_name,
                    "ScheduleExpression": _SCHEDULE_EXPRESSION,
                    "FlexibleTimeWindow": {"Mode": "OFF"},
                    "State": "ENABLED",
                    "Target": {
                        "Arn": {"Fn::GetAtt": ["Queue", "Arn"]},
                        "RoleArn": {"Fn::GetAtt": ["SchedulerRole", "Arn"]},
                        "Input": schedule_input,
                    },
                },
            },
        },
        "Outputs": {
            "GroupRef": {"Value": {"Ref": "Group"}},
            "GroupArn": {"Value": {"Fn::GetAtt": ["Group", "Arn"]}},
            "QueueArn": {"Value": {"Fn::GetAtt": ["Queue", "Arn"]}},
            "RoleArn": {"Value": {"Fn::GetAtt": ["SchedulerRole", "Arn"]}},
            "ScheduleRef": {"Value": {"Ref": "Schedule"}},
            "ScheduleArn": {"Value": {"Fn::GetAtt": ["Schedule", "Arn"]}},
        },
    })


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation Scheduler schedule group and schedule read back through EventBridge Scheduler.

    Ref, GetAtt, every templated property and the group's tag match, and the stack delete removes
    both.
    """
    cfn = ctx.client("cloudformation")
    scheduler = ctx.client("scheduler")

    group_name = ctx.unique_name("sim2real-behav-cfn-schedgrp-")
    queue_name = ctx.unique_name("sim2real-behav-cfn-schedq-")
    role_name = ctx.unique_name("sim2real-behav-cfn-schedrole-")
    schedule_name = ctx.unique_name("sim2real-behav-cfn-sched-")
    schedule_input = json.dumps({"source": "sim2real-provisioning-check"})
    stack = ctx.unique_name("sim2real-behav-cfn-schedstack-")

    stack_id = create_stack(
        ctx, cfn, stack,
        _template(group_name, queue_name, role_name, schedule_name, schedule_input),
        Capabilities=["CAPABILITY_NAMED_IAM"],
    )
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)
    partition = stack_id.split(":")[1]
    arn_prefix = f"arn:{partition}:scheduler:{ctx.region}:{ctx.account}"

    # ScheduleGroup: Ref == the name an independent ListScheduleGroups reports; GetAtt Arn ==
    # the listed and described Arn and the documented format; the stack tag reads back.
    groups = [g for g in paginate(scheduler, "list_schedule_groups", "ScheduleGroups",
                                  NamePrefix=group_name) if g["Name"] == group_name]
    group_arn = f"{arn_prefix}:schedule-group/{group_name}"
    assert [(g["Name"], g["Arn"]) for g in groups] == [(outputs["GroupRef"], group_arn)], (
        f"ListScheduleGroups found {groups!r} for Ref {outputs['GroupRef']!r}"
    )
    group = scheduler.get_schedule_group(Name=group_name)
    got_group = (group["Arn"], outputs["GroupArn"], group["State"])
    assert got_group == (group_arn, group_arn, "ACTIVE"), f"schedule group reads {got_group!r}"
    group_tags = {t["Key"]: t["Value"] for t in scheduler.list_tags_for_resource(
        ResourceArn=group_arn)["Tags"] if not t["Key"].startswith("aws:")}
    assert group_tags == {"sim2real": stack}, f"schedule group tags {group_tags!r}"

    # Schedule: Ref == the name ListSchedules reports in the default group; GetAtt Arn and every
    # templated property read back through GetSchedule.
    schedules = [s for s in paginate(scheduler, "list_schedules", "Schedules",
                                     NamePrefix=schedule_name) if s["Name"] == schedule_name]
    schedule_arn = f"{arn_prefix}:schedule/default/{schedule_name}"
    assert [(s["Name"], s["Arn"]) for s in schedules] == [(outputs["ScheduleRef"], schedule_arn)], (
        f"ListSchedules found {schedules!r} for Ref {outputs['ScheduleRef']!r}"
    )
    schedule = scheduler.get_schedule(Name=schedule_name)
    got = {
        "Arn": schedule["Arn"], "ScheduleExpression": schedule["ScheduleExpression"],
        "FlexibleTimeWindow": schedule["FlexibleTimeWindow"], "State": schedule["State"],
        "Target": {k: schedule["Target"].get(k) for k in ("Arn", "RoleArn", "Input")},
    }
    want = {
        "Arn": outputs["ScheduleArn"], "ScheduleExpression": _SCHEDULE_EXPRESSION,
        "FlexibleTimeWindow": {"Mode": "OFF"}, "State": "ENABLED",
        "Target": {"Arn": outputs["QueueArn"], "RoleArn": outputs["RoleArn"],
                   "Input": schedule_input},
    }
    assert got == want, f"GetSchedule reads {got!r}, expected {want!r}"
    assert outputs["ScheduleArn"] == schedule_arn, f"GetAtt Arn {outputs['ScheduleArn']!r}"

    # The two are siblings (the schedule lives in the default group), so one stack delete proves
    # each type's own delete through Scheduler.
    delete_stack(cfn, stack_id)
    gone = ("ResourceNotFoundException", f"Schedule group {group_name} does not exist.")
    expect_error(lambda: scheduler.get_schedule_group(Name=group_name), *gone)
    gone = ("ResourceNotFoundException", f"Schedule {schedule_name} does not exist.")
    expect_error(lambda: scheduler.get_schedule(Name=schedule_name), *gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
