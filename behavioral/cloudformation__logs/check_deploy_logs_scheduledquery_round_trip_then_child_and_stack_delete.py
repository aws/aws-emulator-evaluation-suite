"""deploy-logs-scheduledquery-round-trip-then-child-and-stack-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-logs-scheduledquery-round-trip-then-child-and-stack-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "logs"]

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


_QUERY_LANGUAGE = "CWLI"
_QUERY_STRING = "fields @timestamp, @message | limit 20"
# A far-future one-shot schedule that cannot fire during the run, combined with State=DISABLED.
_SCHEDULE_EXPRESSION = "cron(0 12 1 1 ? 2099)"
_START_TIME_OFFSET = 3600


def _own_groups(logs, name):
    return [g for g in paginate(logs, "describe_log_groups", "logGroups", logGroupNamePrefix=name)
            if g["logGroupName"] == name]


def _template(group_name, role_name, query_name, with_query=True):
    resources = {
        "LogGroup": {"Type": "AWS::Logs::LogGroup", "Properties": {"LogGroupName": group_name}},
        "Role": {"Type": "AWS::IAM::Role", "Properties": {
            "RoleName": role_name,
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow", "Principal": {"Service": "logs.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }],
            },
            "Policies": [{
                "PolicyName": "ScheduledQueryPolicy",
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Action": ["logs:StartQuery", "logs:StopQuery", "logs:GetQueryResults",
                                   "logs:DescribeLogGroups"],
                        "Resource": {"Fn::Sub": (
                            "arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:"
                            f"log-group:{group_name}:*"
                        )},
                    }],
                },
            }],
        }},
    }
    outputs = {"GroupRef": {"Value": {"Ref": "LogGroup"}}}
    if with_query:
        resources["ScheduledQuery"] = {
            "Type": "AWS::Logs::ScheduledQuery",
            "DependsOn": "Role",
            "Properties": {
                "Name": query_name,
                "QueryLanguage": _QUERY_LANGUAGE,
                "QueryString": _QUERY_STRING,
                "ScheduleExpression": _SCHEDULE_EXPRESSION,
                "StartTimeOffset": _START_TIME_OFFSET,
                "ExecutionRoleArn": {"Fn::GetAtt": ["Role", "Arn"]},
                "LogGroupIdentifiers": [{"Ref": "LogGroup"}],
                "State": "DISABLED",
            },
        }
        outputs["QueryRef"] = {"Value": {"Ref": "ScheduledQuery"}}
        outputs["QueryArn"] = {"Value": {"Fn::GetAtt": ["ScheduledQuery", "ScheduledQueryArn"]}}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09", "Resources": resources, "Outputs": outputs,
    })


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation ScheduledQuery reads back through CloudWatch Logs with its exact
    configuration; an update removing it leaves the log group in place, and deleting the stack
    removes the log group.
    """
    cf = ctx.client("cloudformation")
    logs = ctx.client("logs")
    stack = ctx.unique_name("sim2real-cfnlogs-sq-")
    group = ctx.unique_name("sim2real-cfnlogs-sq-grp-")
    role = ctx.unique_name("sim2real-cfnlogs-sq-role-")
    query_name = ctx.unique_name("sim2real-cfnlogs-sq-qry-")

    stack_id = create_stack(
        ctx, cf, stack, _template(group, role, query_name), Capabilities=["CAPABILITY_NAMED_IAM"],
    )
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    out = stack_outputs(cf, stack_id)
    groups = _own_groups(logs, group)
    assert [g["logGroupName"] for g in groups] == [out["GroupRef"]] == [group], (
        f"Ref LogGroup {out['GroupRef']!r}, listed {groups!r}"
    )

    # Ref and the read-only GetAtt both == the ARN of the query listed under its declared name
    # (never a read keyed by the Ref); every templated property reads back too.
    query_ref = out["QueryRef"]
    listed = [q for q in paginate(logs, "list_scheduled_queries", "scheduledQueries")
              if q["name"] == query_name]
    assert [q["scheduledQueryArn"] for q in listed] == [query_ref], (
        f"ListScheduledQueries entries named {query_name!r}: {listed!r}, Ref {query_ref!r}"
    )
    assert out["QueryArn"] == query_ref, f"GetAtt ScheduledQueryArn {out['QueryArn']!r} != {query_ref!r}"
    sq = logs.get_scheduled_query(identifier=listed[0]["scheduledQueryArn"])
    assert sq["name"] == query_name, f"name {sq['name']!r} != {query_name!r}"
    assert sq["queryLanguage"] == _QUERY_LANGUAGE, f"queryLanguage {sq['queryLanguage']!r}"
    assert sq["queryString"] == _QUERY_STRING, f"queryString {sq['queryString']!r}"
    assert sq["scheduleExpression"] == _SCHEDULE_EXPRESSION, (
        f"scheduleExpression {sq['scheduleExpression']!r}"
    )
    assert sq["startTimeOffset"] == _START_TIME_OFFSET, f"startTimeOffset {sq['startTimeOffset']!r}"
    assert sq["state"] == "DISABLED", f"state {sq['state']!r}"
    assert sq["logGroupIdentifiers"] == [group], (
        f"logGroupIdentifiers {sq['logGroupIdentifiers']!r} != [{group!r}]"
    )

    expected_role_arn = f"arn:{stack_id.split(':')[1]}:iam::{ctx.account}:role/{role}"
    assert sq["executionRoleArn"] == expected_role_arn, (
        f"executionRoleArn {sq['executionRoleArn']!r} != {expected_role_arn!r}"
    )

    # Child before parent: drop the ScheduledQuery, keep LogGroup and Role; the child's own
    # absence through Logs while the log group still answers.
    cf.update_stack(
        StackName=stack_id, TemplateBody=_template(group, role, query_name, with_query=False),
        Capabilities=["CAPABILITY_NAMED_IAM"],
    )
    status = wait_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"child-removing update ended {status!r}"

    still_there = _own_groups(logs, group)
    assert [g["logGroupName"] for g in still_there] == [group], (
        f"LogGroup should still answer after the update, got {still_there!r}"
    )
    not_found = (
        "ResourceNotFoundException",
        f"Scheduled query with identifier {query_ref} not found",
    )
    expect_error(lambda: logs.get_scheduled_query(identifier=query_ref), *not_found)

    delete_stack(cf, stack_id)
    gone = _own_groups(logs, group)
    assert gone == [], f"LogGroup still listed after DeleteStack: {gone!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
