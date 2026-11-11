"""deploy-applicationinsights-application-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-applicationinsights-application-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["application-insights", "cloudformation", "resource-groups"]

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

_APP_NOT_FOUND = ("ResourceNotFoundException", "Application does not exist")
_GROUP_NOT_FOUND = ("NotFoundException", "The specified group does not exist")


def _template(group_name, app_group):
    """A tag-query resource group and an Application; ``app_group`` names the app's group."""
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Group": {
                "Type": "AWS::ResourceGroups::Group",
                "Properties": {
                    "Name": group_name,
                    "ResourceQuery": {
                        "Type": "TAG_FILTERS_1_0",
                        "Query": {
                            "ResourceTypeFilters": ["AWS::AllSupported"],
                            "TagFilters": [{"Key": "sim2real", "Values": [group_name]}],
                        },
                    },
                },
            },
            "App": {
                "Type": "AWS::ApplicationInsights::Application",
                "DependsOn": "Group",
                "Properties": {"ResourceGroupName": app_group, "AutoConfigurationEnabled": False},
            },
        },
        "Outputs": {
            "GroupName": {"Value": {"Ref": "Group"}},
            "GroupArn": {"Value": {"Fn::GetAtt": ["Group", "Arn"]}},
            "AppArn": {"Value": {"Ref": "App"}},
        },
    })


def _applications(ai):
    """Every ListApplications entry; the operation has no paginator, so NextToken is walked."""
    items, kw = [], {}
    while True:
        page = ai.list_applications(**kw)
        items += page.get("ApplicationInfoList", [])
        if not page.get("NextToken"):
            return items
        kw["NextToken"] = page["NextToken"]


def _groups_named(rg, name):
    return [g for g in paginate(rg, "list_groups", "GroupIdentifiers") if g["GroupName"] == name]


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation Application Insights application reads back on its own resource group.

    Refs match independent listings; an update dropping the application removes it while the
    same group answers, and deleting the stack removes the group.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-applicationinsights-application.html
    """
    cfn = ctx.client("cloudformation")
    ai = ctx.client("application-insights")
    rg = ctx.client("resource-groups")
    stack = ctx.unique_name("sim2real-aiapp-")
    group_name = ctx.unique_name("sim2real-aigrp-")

    stack_id = create_stack(ctx, cfn, stack, _template(group_name, {"Ref": "Group"}))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    partition = stack_id.split(":")[1]

    # The group's Ref and GetAtt against an independent ListGroups read by name.
    group_arn = f"arn:{partition}:resource-groups:{ctx.region}:{ctx.account}:group/{group_name}"
    listed = [g["GroupArn"] for g in _groups_named(rg, group_name)]
    assert listed == [group_arn], f"ListGroups found {listed!r}, expected {group_arn!r}"
    assert (out["GroupName"], out["GroupArn"]) == (group_name, group_arn), (
        f"Group Ref/Arn {(out['GroupName'], out['GroupArn'])!r}"
    )
    query = rg.get_group_query(GroupName=group_name)["GroupQuery"]["ResourceQuery"]
    query = json.loads(query["Query"])
    want = {"ResourceTypeFilters": ["AWS::AllSupported"],
            "TagFilters": [{"Key": "sim2real", "Values": [group_name]}]}
    assert query == want, f"GetGroupQuery returned {query!r}, expected {want!r}"

    # The application's Ref against the documented ARN, and its properties from an independent
    # ListApplications entry and DescribeApplication.
    app_arn = (f"arn:{partition}:applicationinsights:{ctx.region}:{ctx.account}:"
               f"application/resource-group/{group_name}")
    assert out["AppArn"] == app_arn, f"Application Ref {out['AppArn']!r} != {app_arn!r}"
    listed = [(a["ResourceGroupName"], a["AutoConfigEnabled"]) for a in _applications(ai)
              if a["ResourceGroupName"] == group_name]
    assert listed == [(group_name, False)], f"ListApplications found {listed!r}"
    app = ai.describe_application(ResourceGroupName=group_name)["ApplicationInfo"]
    got = (app["ResourceGroupName"], app["AutoConfigEnabled"])
    assert got == (group_name, False), f"DescribeApplication reads {got!r}"

    # Child before parent: an update dropping only the application removes it while the group
    # it monitors still answers.
    removed = json.loads(_template(group_name, {"Ref": "Group"}))
    del removed["Resources"]["App"], removed["Outputs"]["AppArn"]
    cfn.update_stack(StackName=stack_id, TemplateBody=json.dumps(removed))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"application-removing update ended {status!r}"
    until_raises(lambda: ai.describe_application(ResourceGroupName=group_name))
    expect_error(lambda: ai.describe_application(ResourceGroupName=group_name), *_APP_NOT_FOUND)
    assert rg.get_group(GroupName=group_name)["Group"]["GroupArn"] == group_arn, (
        "the resource group no longer answers after the application's removal"
    )

    delete_stack(cfn, stack_id)
    until_raises(lambda: rg.get_group(GroupName=group_name))
    expect_error(lambda: rg.get_group(GroupName=group_name), *_GROUP_NOT_FOUND)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
