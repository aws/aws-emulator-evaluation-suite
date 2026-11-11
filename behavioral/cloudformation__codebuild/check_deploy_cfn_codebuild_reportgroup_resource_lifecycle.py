"""deploy-cfn-codebuild-reportgroup-resource-lifecycle."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-cfn-codebuild-reportgroup-resource-lifecycle"
GROUP = "deploy"
SERVICES = ["cloudformation", "codebuild"]

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


# ---- Check-specific: the template, then run(). ----

def _template(report_group_name: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "ReportGroup": {
                    "Type": "AWS::CodeBuild::ReportGroup",
                    "Properties": {
                        "Name": report_group_name,
                        "Type": "TEST",
                        "ExportConfig": {"ExportConfigType": "NO_EXPORT"},
                        "DeleteReports": True,
                    },
                },
            },
            "Outputs": {
                "ReportGroupRef": {"Value": {"Ref": "ReportGroup"}},
                "ReportGroupArn": {"Value": {"Fn::GetAtt": ["ReportGroup", "Arn"]}},
            },
        }
    )


@tags(
    "axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control",
)
def run(ctx) -> None:
    """A CloudFormation AWS::CodeBuild::ReportGroup reaches CREATE_COMPLETE with Ref and
    Fn::GetAtt Arn matching its physical id and BatchGetReportGroups reflecting its Type
    and ExportConfig, and deleting the stack removes it from BatchGetReportGroups."""
    cf = ctx.client("cloudformation")
    codebuild = ctx.client("codebuild")

    report_group_name = ctx.unique_name("sim2real-behav-cfnrg-")
    stack_name = ctx.unique_name("sim2real-behav-stack-")

    stack_id = create_stack(ctx, cf, stack_name, _template(report_group_name))
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", f"stack ended in {status!r}, not CREATE_COMPLETE"

    outputs = stack_outputs(cf, stack_id)
    physical_id = cf.describe_stack_resource(
        StackName=stack_id, LogicalResourceId="ReportGroup"
    )["StackResourceDetail"]["PhysicalResourceId"]
    want_arn = f"arn:{stack_id.split(':')[1]}:codebuild:{ctx.region}:{ctx.account}:report-group/{report_group_name}"
    assert physical_id == want_arn, (
        f"expected the PhysicalResourceId to be the report group's documented ARN, got {physical_id!r}"
    )
    assert outputs["ReportGroupRef"] == physical_id, (
        f"expected Ref to equal the resource's PhysicalResourceId {physical_id!r}, "
        f"got {outputs['ReportGroupRef']!r}"
    )
    assert outputs["ReportGroupArn"] == physical_id, (
        f"expected Fn::GetAtt Arn to equal the resource's PhysicalResourceId {physical_id!r}, "
        f"got {outputs['ReportGroupArn']!r}"
    )

    batch_resp = codebuild.batch_get_report_groups(reportGroupArns=[physical_id])
    assert batch_resp["reportGroupsNotFound"] == [], (
        f"expected no not-found entries, got {batch_resp['reportGroupsNotFound']!r}"
    )
    assert len(batch_resp["reportGroups"]) == 1, (
        f"expected one report group, got {len(batch_resp['reportGroups'])}"
    )
    report_group = batch_resp["reportGroups"][0]
    assert report_group["arn"] == physical_id, (
        f"expected BatchGetReportGroups arn to equal Ref {physical_id!r}, got {report_group['arn']!r}"
    )
    assert report_group["name"] == report_group_name, (
        f"expected name {report_group_name!r}, got {report_group['name']!r}"
    )
    assert report_group["type"] == "TEST", f"expected type TEST, got {report_group['type']!r}"
    assert report_group["exportConfig"]["exportConfigType"] == "NO_EXPORT", (
        f"expected exportConfig.exportConfigType NO_EXPORT, got "
        f"{report_group['exportConfig']['exportConfigType']!r}"
    )

    delete_stack(cf, stack_id)

    after = codebuild.batch_get_report_groups(reportGroupArns=[physical_id])
    assert after["reportGroups"] == [], (
        f"expected the report group gone, still described: {after['reportGroups']}"
    )
    assert after["reportGroupsNotFound"] == [physical_id], (
        f"expected {[physical_id]!r} in reportGroupsNotFound, got {after['reportGroupsNotFound']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
