"""deploy-pi-perfreports-round-trip-then-stack-delete."""
from __future__ import annotations

import json
import secrets
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-pi-perfreports-round-trip-then-stack-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "pi", "rds"]

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


def until_raises(fn, timeout_s=90.0):
    """Poll ``fn()`` every 2 s until it raises a ClientError (an eventually consistent delete).

    Grade the error afterwards with expect_error; a success past the deadline fails.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError:
            return
        if time.monotonic() > deadline:
            raise AssertionError(f"still answering after {timeout_s:.0f}s: {result!r}")
        time.sleep(2)


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


def _db_template(db_id, vpc_id, subnet_ids):
    """A private MySQL instance with Database Insights advanced; its password is a NoEcho
    parameter generated per run."""
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"DbPassword": {"Type": "String", "NoEcho": True}},
        "Resources": {
            "DbSecurityGroup": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "sim2real pi perfreports db, no ingress or egress",
                    "VpcId": vpc_id,
                    "SecurityGroupEgress": [
                        {"IpProtocol": "-1", "CidrIp": "127.0.0.1/32",
                         "Description": "no real egress: loopback only, unreachable from the ENI"}
                    ],
                },
            },
            "DbSubnetGroup": {
                "Type": "AWS::RDS::DBSubnetGroup",
                "Properties": {
                    "DBSubnetGroupDescription": "sim2real pi perfreports",
                    "SubnetIds": subnet_ids,
                },
            },
            "DbInstance": {
                "Type": "AWS::RDS::DBInstance",
                "DeletionPolicy": "Delete",
                "Properties": {
                    "DBInstanceIdentifier": db_id,
                    "DBInstanceClass": "db.t3.medium",
                    "Engine": "mysql",
                    "MasterUsername": "piadmin",
                    "MasterUserPassword": {"Ref": "DbPassword"},
                    "AllocatedStorage": 20,
                    "StorageType": "gp2",
                    "EnablePerformanceInsights": True,
                    "DatabaseInsightsMode": "advanced",
                    "PerformanceInsightsRetentionPeriod": 465,
                    "BackupRetentionPeriod": 0,
                    "PubliclyAccessible": False,
                    "MultiAZ": False,
                    "DBSubnetGroupName": {"Ref": "DbSubnetGroup"},
                    "VPCSecurityGroups": [{"Ref": "DbSecurityGroup"}],
                    "Tags": [{"Key": "sim2real-db", "Value": db_id}],
                },
            },
        },
        "Outputs": {
            "DbiResourceId": {"Value": {"Fn::GetAtt": ["DbInstance", "DbiResourceId"]}},
            "DbInstanceArn": {"Value": {"Fn::GetAtt": ["DbInstance", "DBInstanceArn"]}},
        },
    })


def _report_template(dbi, start_iso, end_iso, report_tag_value):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Report": {
                "Type": "AWS::PI::PerfReports",
                "Properties": {
                    "ServiceType": "RDS",
                    "Identifier": dbi,
                    "StartTime": start_iso,
                    "EndTime": end_iso,
                    "Tags": [{"Key": "sim2real-report", "Value": report_tag_value}],
                },
            }
        },
        "Outputs": {
            "ReportRef": {"Value": {"Ref": "Report"}},
            "ReportId": {"Value": {"Fn::GetAtt": ["Report", "AnalysisReportId"]}},
            "ReportCreateTime": {"Value": {"Fn::GetAtt": ["Report", "CreateTime"]}},
            "ReportStatus": {"Value": {"Fn::GetAtt": ["Report", "Status"]}},
        },
    })


def _list_all_reports(pi, service_type, identifier):
    """Every AnalysisReport from ListPerformanceAnalysisReports (no boto3 paginator for this op)."""
    reports = []
    kwargs = {"ServiceType": service_type, "Identifier": identifier, "MaxResults": 25,
              "ListTags": True}
    while True:
        page = pi.list_performance_analysis_reports(**kwargs)
        reports.extend(page.get("AnalysisReports", []))
        token = page.get("NextToken")
        if not token:
            return reports
        kwargs["NextToken"] = token


_REPORT_GONE = (
    "NotAuthorizedException",
    "The specified resource is not authorized for this account",
)
#: A db.t3.medium MySQL instance takes minutes to create and to delete.
_DB_CREATE_S = 1500.0
_DB_DELETE_S = 1500.0


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s; last={last!r}")


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """An AWS::PI::PerfReports resource on a fresh Performance-Insights-advanced RDS instance
    reaches CREATE_COMPLETE with a report RDS and PI agree about; deleting its stack removes the
    report while the instance answers, and the DB stack delete removes the instance.
    """
    cf = ctx.client("cloudformation")
    rds = ctx.client("rds")
    pi = ctx.client("pi")
    network = ctx.network()

    db_id = ctx.unique_name("sim2real-pifr-db-")
    net_stack_name = ctx.unique_name("sim2real-pifr-net-")
    net_stack_id = create_stack(
        ctx, cf, net_stack_name, _db_template(db_id, network.vpc_id, network.subnet_ids[:2]),
        Parameters=[{"ParameterKey": "DbPassword",
                     "ParameterValue": secrets.token_urlsafe(18)}],
    )
    status = wait_stack(cf, net_stack_id, timeout_s=_DB_CREATE_S)
    assert status == "CREATE_COMPLETE", (
        f"DB stack ended {status!r}: {decisive_rows(stack_events(cf, net_stack_id))!r}"
    )
    net_out = stack_outputs(cf, net_stack_id)
    dbi = net_out["DbiResourceId"]

    # Independent read: RDS's own instance, by the declared identifier.
    desc = rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0]
    got = (desc["DbiResourceId"], desc["DBInstanceArn"], desc.get("DatabaseInsightsMode"),
           desc["DBInstanceStatus"])
    assert got == (dbi, net_out["DbInstanceArn"], "advanced", "available"), (
        f"RDS (DbiResourceId, arn, insights mode, status) {got!r}, GetAtt DbiResourceId {dbi!r}"
    )
    db_tags = {t["Key"]: t["Value"] for t in desc.get("TagList", [])
               if not t["Key"].startswith("aws:")}
    assert db_tags == {"sim2real": net_stack_name, "sim2real-db": db_id}, f"DB tags {db_tags!r}"

    now = datetime.now(timezone.utc).replace(microsecond=0)
    start = now - timedelta(minutes=20)
    end = now - timedelta(minutes=5)
    report_tag_value = ctx.unique_name("sim2real-pifr-reporttag-")
    report_stack_name = ctx.unique_name("sim2real-pifr-report-")
    report_stack_id = create_stack(
        ctx, cf, report_stack_name,
        _report_template(dbi, start.isoformat(), end.isoformat(), report_tag_value),
    )
    status = wait_stack(cf, report_stack_id)
    assert status == "CREATE_COMPLETE", (
        f"report stack ended {status!r}: {decisive_rows(stack_events(cf, report_stack_id))!r}"
    )
    report_out = stack_outputs(cf, report_stack_id)
    report_arn = report_out["ReportRef"]
    report_id = report_out["ReportId"]

    # Ref's exact ARN shape: partition from this stack's own ARN, never hardcoded.
    partition = report_stack_id.split(":", 2)[1]
    expected_arn = (
        f"arn:{partition}:pi:{ctx.region}:{ctx.account}:perf-reports/RDS/{dbi}/{report_id}"
    )
    assert report_arn == expected_arn, f"Ref {report_arn!r} != expected {expected_arn!r}"

    # Independent list read (never a read keyed by Ref/GetAtt): the report and its tags.
    matches = [r for r in _list_all_reports(pi, "RDS", dbi) if r["AnalysisReportId"] == report_id]
    assert len(matches) == 1, f"expected exactly one listed report {report_id!r}, got {matches!r}"
    listed_tags = {t["Key"]: t["Value"] for t in matches[0].get("Tags", [])}
    assert listed_tags == {"sim2real": report_stack_name, "sim2real-report": report_tag_value}, (
        f"ListPerformanceAnalysisReports tags are {listed_tags!r}"
    )

    # Every templated property and the read-only GetAtts, echoed back by PI directly.
    got = pi.get_performance_analysis_report(
        ServiceType="RDS", Identifier=dbi, AnalysisReportId=report_id
    )["AnalysisReport"]
    assert (got["AnalysisReportId"], got["Identifier"], got["ServiceType"], got["StartTime"],
            got["EndTime"]) == (report_id, dbi, "RDS", start, end), f"PI report reads {got!r}"
    getatt_create_time = datetime.strptime(
        report_out["ReportCreateTime"], "%Y-%m-%dT%H:%M:%S.%fZ"
    ).replace(tzinfo=timezone.utc)
    assert (getatt_create_time, report_out["ReportStatus"]) == (got["CreateTime"], got["Status"]), (
        f"GetAtt (CreateTime, Status) {(report_out['ReportCreateTime'], report_out['ReportStatus'])!r}"
        f" != PI {(got['CreateTime'], got['Status'])!r}"
    )

    # The report reaches a terminal PI state before its delete is a meaningful "gone" claim.
    final = _poll_until(
        lambda: pi.get_performance_analysis_report(
            ServiceType="RDS", Identifier=dbi, AnalysisReportId=report_id
        )["AnalysisReport"],
        lambda r: r["Status"] != "RUNNING",
        timeout_s=900.0,
        interval_s=15.0,
    )
    assert final["Status"] == "SUCCEEDED", f"analysis report ended in {final['Status']!r}"

    # Child first: the report's stack goes while its DB instance still answers.
    delete_stack(cf, report_stack_id)
    until_raises(lambda: pi.get_performance_analysis_report(
        ServiceType="RDS", Identifier=dbi, AnalysisReportId=report_id
    ))
    expect_error(
        lambda: pi.get_performance_analysis_report(
            ServiceType="RDS", Identifier=dbi, AnalysisReportId=report_id
        ),
        *_REPORT_GONE,
    )
    assert rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0][
        "DbiResourceId"
    ] == dbi, "the DB instance stopped answering when only the report was deleted"

    # The instance's delete outlasts the helpers' per-stack budget: wait for it explicitly.
    cf.delete_stack(StackName=net_stack_id)
    status = wait_stack(cf, net_stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"}, _DB_DELETE_S)
    assert status == "DELETE_COMPLETE", (
        f"DB stack delete ended {status!r}: {decisive_rows(stack_events(cf, net_stack_id))!r}"
    )
    db_gone = ("DBInstanceNotFound", f"DBInstance {db_id} not found.")
    expect_error(lambda: rds.describe_db_instances(DBInstanceIdentifier=db_id), *db_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
