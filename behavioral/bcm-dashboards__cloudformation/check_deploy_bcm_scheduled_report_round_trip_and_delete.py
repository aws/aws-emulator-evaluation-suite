"""deploy-bcm-scheduled-report-round-trip-and-delete."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-bcm-scheduled-report-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["bcm-dashboards", "cloudformation"]

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

_SCHEDULE = "cron(0 8 1 6 ? 2028)"
_TIME_ZONE = "UTC"


def _cost_widget(title: str) -> dict:
    return {
        "Title": title,
        "Configs": [
            {
                "QueryParameters": {
                    "CostAndUsage": {
                        "Metrics": ["UnblendedCost"],
                        "TimeRange": {
                            "StartTime": {"Type": "RELATIVE", "Value": "-P1M"},
                            "EndTime": {"Type": "RELATIVE", "Value": "-P0D"},
                        },
                        "Granularity": "MONTHLY",
                    }
                },
                "DisplayConfig": {"Table": {}},
            }
        ],
    }


def _template(dash_name: str, report_name: str, *, with_report: bool = True) -> str:
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "bcm-dashboards.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    body = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ExecRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": trust_policy,
                    "Policies": [{
                        "PolicyName": "scheduled-report-read",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "bcm-dashboards:GetDashboard",
                                    "Resource": {"Ref": "Dashboard"},
                                },
                                {
                                    "Effect": "Allow",
                                    "Action": "ce:GetCostAndUsage",
                                    "Resource": "*",
                                },
                            ],
                        },
                    }],
                },
            },
            "Dashboard": {
                "Type": "AWS::BCM::Dashboard",
                "Properties": {
                    "Name": dash_name,
                    "Widgets": [_cost_widget("Report Widget")],
                },
            },
            "ScheduledReport": {
                "Type": "AWS::BCM::ScheduledReport",
                "Properties": {
                    "Name": report_name,
                    "DashboardArn": {"Ref": "Dashboard"},
                    "ScheduledReportExecutionRoleArn": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                    "ScheduleConfig": {
                        "ScheduleExpression": _SCHEDULE,
                        "ScheduleExpressionTimeZone": _TIME_ZONE,
                        "State": "DISABLED",
                    },
                },
            },
        },
        "Outputs": {
            "ReportArn": {"Value": {"Ref": "ScheduledReport"}},
            "ReportCreatedAt": {"Value": {"Fn::GetAtt": ["ScheduledReport", "CreatedAt"]}},
            "DashboardArn": {"Value": {"Ref": "Dashboard"}},
            "RoleArn": {"Value": {"Fn::GetAtt": ["ExecRole", "Arn"]}},
        },
    }
    if not with_report:
        del body["Resources"]["ScheduledReport"]
        for key in ("ReportArn", "ReportCreatedAt"):
            del body["Outputs"][key]
    return json.dumps(body)


def _iso_millis(value: datetime.datetime) -> str:
    """A botocore timestamp formatted to match a CloudFormation Fn::GetAtt date-time output."""
    utc = value.astimezone(datetime.timezone.utc)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{utc.microsecond // 1000:03d}Z"


def _create_stack_retrying_role_propagation(ctx, cf, stack: str, template: str,
                                             *, timeout_s: float = 240, interval_s: float = 10):
    """ScheduledReport's create validates the execution role is assumable; a just-created IAM
    role can take a few seconds to propagate, so a stack whose only failure is that specific
    reason is retried end to end rather than treated as a hard failure.

    Returns ``(stack id, status)``.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        stack_id = create_stack(ctx, cf, stack, template, Capabilities=["CAPABILITY_IAM"])
        status = wait_stack(cf, stack_id)
        if status == "CREATE_COMPLETE":
            return stack_id, status
        reasons = [e.get("ResourceStatusReason") for e in stack_events(cf, stack_id)
                   if e["LogicalResourceId"] == "ScheduledReport"
                   and e["ResourceStatus"] == "CREATE_FAILED"]
        reason = reasons[0] if len(reasons) == 1 else None
        if reason is not None and "assume" in reason.lower() and time.monotonic() < deadline:
            delete_stack(cf, stack_id)
            time.sleep(interval_s)
            continue
        return stack_id, status


def _listed(bcm, op: str, key: str, name: str) -> list[str]:
    """Every arn the ``key`` list of ``op`` reports under ``name``, all pages read."""
    return [r["arn"] for r in paginate(bcm, op, key) if r["name"] == name]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::BCM::ScheduledReport and its dashboard read back with the declared
    properties and read-only CreatedAt; removing the report from the stack deletes it while the
    dashboard stays, and deleting the stack removes the dashboard.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-bcm-scheduledreport.html
    """
    bcm = ctx.client("bcm-dashboards")
    cf = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-bcmsr-")
    dash_name = ctx.unique_name("sim2real-bcmdash-")
    report_name = ctx.unique_name("sim2real-bcmsr-")
    template = _template(dash_name, report_name)

    stack_gone = ("ValidationError", f"Stack with id {stack} does not exist")
    stack_id, status = _create_stack_retrying_role_propagation(ctx, cf, stack, template)
    assert status == "CREATE_COMPLETE", f"stack {stack!r} ended {status!r}, expected CREATE_COMPLETE"

    outputs = stack_outputs(cf, stack_id)
    report_arn = outputs["ReportArn"]
    dashboard_arn = outputs["DashboardArn"]
    role_arn = outputs["RoleArn"]
    listed = _listed(bcm, "list_scheduled_reports", "scheduledReports", report_name)
    assert listed == [report_arn], (
        f"expected ListScheduledReports to name {report_name!r} once at the Ref, got {listed!r}"
    )
    listed = _listed(bcm, "list_dashboards", "dashboards", dash_name)
    assert listed == [dashboard_arn], (
        f"expected ListDashboards to name {dash_name!r} once at the Ref, got {listed!r}"
    )
    dashboard = bcm.get_dashboard(arn=dashboard_arn)
    assert dashboard["name"] == dash_name, (
        f"expected the dashboard's Name {dash_name!r} to read back, got {dashboard['name']!r}"
    )
    titles = [w["title"] for w in dashboard["widgets"]]
    assert titles == ["Report Widget"], f"expected the dashboard's one widget title, got {titles!r}"

    physical_id = cf.describe_stack_resource(
        StackName=stack_id, LogicalResourceId="ScheduledReport"
    )["StackResourceDetail"]["PhysicalResourceId"]
    assert physical_id == report_arn, (
        f"expected the ScheduledReport resource's PhysicalResourceId to equal its Ref "
        f"{report_arn!r}, CloudFormation reports {physical_id!r}"
    )

    got = bcm.get_scheduled_report(arn=report_arn)["scheduledReport"]
    assert got["arn"] == report_arn, f"expected arn {report_arn!r}, bcm-dashboards reports {got['arn']!r}"
    assert got["name"] == report_name, (
        f"expected the template's Name {report_name!r} to read back, bcm-dashboards reports "
        f"{got['name']!r}"
    )
    assert got["dashboardArn"] == dashboard_arn, (
        f"expected dashboardArn {dashboard_arn!r}, bcm-dashboards reports {got['dashboardArn']!r}"
    )
    assert got["scheduledReportExecutionRoleArn"] == role_arn, (
        f"expected scheduledReportExecutionRoleArn {role_arn!r}, bcm-dashboards reports "
        f"{got['scheduledReportExecutionRoleArn']!r}"
    )
    schedule = got["scheduleConfig"]
    got_schedule = (schedule["scheduleExpression"], schedule["scheduleExpressionTimeZone"],
                    schedule["state"])
    assert got_schedule == (_SCHEDULE, _TIME_ZONE, "DISABLED"), (
        f"expected the template's ScheduleConfig {(_SCHEDULE, _TIME_ZONE, 'DISABLED')!r} to read "
        f"back, bcm-dashboards reports {got_schedule!r}"
    )
    created_at = _iso_millis(got["createdAt"])
    assert created_at == outputs["ReportCreatedAt"], (
        f"expected GetAtt CreatedAt {outputs['ReportCreatedAt']!r} to equal GetScheduledReport's "
        f"{created_at!r}"
    )

    cf.update_stack(StackName=stack_id,
                    TemplateBody=_template(dash_name, report_name, with_report=False),
                    Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"stack {stack!r} ended {status!r}, expected UPDATE_COMPLETE"
    report_gone = ("ResourceNotFoundException", f"Scheduled report not found: {report_arn}")
    expect_error(lambda: bcm.get_scheduled_report(arn=report_arn), *report_gone)
    assert bcm.get_dashboard(arn=dashboard_arn)["name"] == dash_name, (
        "expected the dashboard to survive the report's removal from the stack"
    )

    delete_stack(cf, stack_id)
    expect_error(lambda: cf.describe_stacks(StackName=stack), *stack_gone)

    dashboard_gone = ("ResourceNotFoundException", f"Resource {dashboard_arn} does not exist.")
    expect_error(lambda: bcm.get_dashboard(arn=dashboard_arn), *dashboard_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
