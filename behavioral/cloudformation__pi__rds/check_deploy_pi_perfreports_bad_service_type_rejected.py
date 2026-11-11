"""deploy-pi-perfreports-bad-service-type-rejected."""
from __future__ import annotations

import json
import secrets
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "deploy-pi-perfreports-bad-service-type-rejected"
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


def validation_rows(cf, stack_id):
    """Sorted ``(logical id, ValidationName, Status, FailureMode, Reason, Path)`` rows."""
    return sorted(
        (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
         e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
        for e in paginate(cf, "describe_events", "OperationEvents", StackName=stack_id)
        if e.get("EventType") == "VALIDATION_ERROR"
    )


# ---- Check-specific: the template, then run(). ----

#: A db.t3.medium MySQL instance takes minutes to create and to delete.
_DB_CREATE_S = 1500.0
_DB_DELETE_S = 1500.0
_REJECTED = [(
    "Report", "PROPERTY_VALIDATION", "FAILED", "FAIL",
    "MYSQL is not a valid enum value. Supported values: [RDS, DOCDB]",
    "/Resources/Report/Properties/ServiceType",
)]


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


def _report_template(service_type, dbi, start_iso, end_iso, report_tag_value):
    """One report; only its ServiceType varies between the control and the negative."""
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Report": {
                "Type": "AWS::PI::PerfReports",
                "Properties": {
                    "ServiceType": service_type,
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


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """An AWS::PI::PerfReports whose ServiceType is outside {RDS, DOCDB} is refused by early
    validation at its exact path and no report exists, while the same template with RDS on a real
    Performance-Insights instance deploys a report PI lists.
    """
    cf = ctx.client("cloudformation")
    rds = ctx.client("rds")
    pi = ctx.client("pi")
    network = ctx.network()

    # The one real dependency both reports name: a Performance-Insights-advanced DB instance.
    db_id = ctx.unique_name("sim2real-pifr-db-")
    db_stack_id = create_stack(
        ctx, cf, ctx.unique_name("sim2real-pifr-net-"),
        _db_template(db_id, network.vpc_id, network.subnet_ids[:2]),
        Parameters=[{"ParameterKey": "DbPassword",
                     "ParameterValue": secrets.token_urlsafe(18)}],
    )
    status = wait_stack(cf, db_stack_id, timeout_s=_DB_CREATE_S)
    assert status == "CREATE_COMPLETE", (
        f"DB stack ended {status!r}: {decisive_rows(stack_events(cf, db_stack_id))!r}"
    )
    dbi = stack_outputs(cf, db_stack_id)["DbiResourceId"]
    desc = rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0]
    assert (desc["DbiResourceId"], desc["DBInstanceStatus"]) == (dbi, "available"), (
        f"RDS reads {(desc['DbiResourceId'], desc['DBInstanceStatus'])!r}, GetAtt {dbi!r}"
    )
    now = datetime.now(timezone.utc).replace(microsecond=0)
    start, end = (now - timedelta(minutes=20)).isoformat(), (now - timedelta(minutes=5)).isoformat()

    # The one change: ServiceType outside the enum; early validation refuses it before any PI call.
    bad_stack = ctx.unique_name("sim2real-pifr-bad-")
    bad_id = create_stack(ctx, cf, bad_stack, _report_template("MYSQL", dbi, start, end, bad_stack))
    status = wait_stack(cf, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    rows = [r for r in validation_rows(cf, bad_id) if r[3] == "FAIL"]
    assert rows == _REJECTED, f"VALIDATION_ERROR rows {rows!r}, expected {_REJECTED!r}"
    # No report reached PI for the instance, read before any delete.
    assert _list_all_reports(pi, "RDS", dbi) == [], "a report exists after the rejected create"
    # Its stack holds nothing: drop it now so cleanup carries two stacks at most.
    delete_stack(cf, bad_id)

    # Positive control: the same template with ServiceType RDS.
    good_stack = ctx.unique_name("sim2real-pifr-good-")
    good_id = create_stack(ctx, cf, good_stack, _report_template("RDS", dbi, start, end, good_stack))
    status = wait_stack(cf, good_id)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}: {decisive_rows(stack_events(cf, good_id))!r}"
    )
    report_id = stack_outputs(cf, good_id)["ReportId"]
    listed = [r["AnalysisReportId"] for r in _list_all_reports(pi, "RDS", dbi)]
    assert listed == [report_id], (
        f"ListPerformanceAnalysisReports {listed!r}, GetAtt AnalysisReportId {report_id!r}"
    )

    # The report goes first; the instance's delete outlasts the helpers' per-stack budget, so
    # its stack is deleted and waited out here.
    delete_stack(cf, good_id)
    cf.delete_stack(StackName=db_stack_id)
    status = wait_stack(cf, db_stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"}, _DB_DELETE_S)
    assert status == "DELETE_COMPLETE", (
        f"DB stack delete ended {status!r}: {decisive_rows(stack_events(cf, db_stack_id))!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
