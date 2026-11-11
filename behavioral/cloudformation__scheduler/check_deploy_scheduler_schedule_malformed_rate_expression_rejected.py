"""deploy-scheduler-schedule-malformed-rate-expression-rejected."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-scheduler-schedule-malformed-rate-expression-rejected"
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


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


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

_GOOD_EXPRESSION = "rate(5 minutes)"
_BAD_EXPRESSION = "rate(five minutes)"

# CloudFormation's resource-handler wrapping of the Scheduler error; the request id and token vary.
_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*) \(Service: (?P<service>[A-Za-z0-9]+), '
    r'Status Code: (?P<status>\d+), Request ID: [^)]*\)(?: \(SDK Attempt Count: \d+\))?" '
    r'\(RequestToken: [^,]*, HandlerErrorCode: (?P<handler>[A-Za-z]+)\)$'
)


def _template(schedule_name, expression):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Queue": {"Type": "AWS::SQS::Queue", "Properties": {}},
            "SchedulerRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
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
                                "Effect": "Allow", "Action": "sqs:SendMessage",
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
                    "ScheduleExpression": expression,
                    "FlexibleTimeWindow": {"Mode": "OFF"},
                    "Target": {"Arn": {"Fn::GetAtt": ["Queue", "Arn"]},
                               "RoleArn": {"Fn::GetAtt": ["SchedulerRole", "Arn"]}},
                },
            },
        },
        "Outputs": {
            "QueueArn": {"Value": {"Fn::GetAtt": ["Queue", "Arn"]}},
            "RoleArn": {"Value": {"Fn::GetAtt": ["SchedulerRole", "Arn"]}},
        },
    })


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:deploy", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation Scheduler schedule with a malformed rate() expression fails in Scheduler.

    The handler names the expression and no such schedule exists, while the same template with a
    valid rate() expression deploys.
    """
    cfn = ctx.client("cloudformation")
    scheduler = ctx.client("scheduler")
    good_schedule = ctx.unique_name("sim2real-behav-cfnok-sched-")
    bad_schedule = ctx.unique_name("sim2real-behav-cfnbad-sched-")

    # Positive control: the same template with a valid rate expression, through CloudFormation.
    good_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-stack-ok-"),
                           _template(good_schedule, _GOOD_EXPRESSION),
                           Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cfn, good_id)
    assert status == "CREATE_COMPLETE", f"control stack ended {status!r}"
    out = stack_outputs(cfn, good_id)
    listed = [s["Name"] for s in paginate(scheduler, "list_schedules", "Schedules",
                                          NamePrefix=good_schedule)]
    assert listed == [good_schedule], f"ListSchedules found {listed!r} for {good_schedule!r}"
    good = scheduler.get_schedule(Name=good_schedule)
    got = (good["ScheduleExpression"], good["Target"]["Arn"], good["Target"]["RoleArn"])
    assert got == (_GOOD_EXPRESSION, out["QueueArn"], out["RoleArn"]), f"control reads {got!r}"

    # The one thing broken: a rate() expression Scheduler does not accept. DisableRollback keeps
    # the CREATE_FAILED row as the stack's last word on the schedule.
    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-stack-bad-"),
                          _template(bad_schedule, _BAD_EXPRESSION),
                          Capabilities=["CAPABILITY_IAM"], DisableRollback=True)
    status = wait_stack(cfn, bad_id)
    assert status == "CREATE_FAILED", f"rejected stack ended {status!r}"
    reason = failed_reason(stack_events(cfn, bad_id), "Schedule")
    match = _REASON.match(reason or "")
    assert match is not None, f"CREATE_FAILED reason is not a resource-handler message: {reason!r}"
    got_error = (match["message"], match["service"], match["status"], match["handler"])
    want_error = (
        f"Invalid request provided: Invalid Schedule Expression {_BAD_EXPRESSION}.",
        "Scheduler", "400", "InvalidRequest",
    )
    assert got_error == want_error, f"CREATE_FAILED reason {got_error!r}, expected {want_error!r}"

    # Absence through Scheduler, by the name the schedule would have, before any delete.
    gone = ("ResourceNotFoundException", f"Schedule {bad_schedule} does not exist.")
    expect_error(lambda: scheduler.get_schedule(Name=bad_schedule), *gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
