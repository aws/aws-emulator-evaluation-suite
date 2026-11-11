"""deploy-resourcegroups-group-tag-query-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-resourcegroups-group-tag-query-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "resource-groups"]

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

_GROUP_NOT_FOUND = ("NotFoundException", "The specified group does not exist")
_STACK_GONE = "Stack with id {} does not exist"


def _template(group_name: str, description: str, tag_value: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Group": {
                "Type": "AWS::ResourceGroups::Group",
                "Properties": {
                    "Name": group_name,
                    "Description": description,
                    "ResourceQuery": {
                        "Type": "TAG_FILTERS_1_0",
                        "Query": {
                            "ResourceTypeFilters": ["AWS::AllSupported"],
                            "TagFilters": [{"Key": "sim2real", "Values": [tag_value]}],
                        },
                    },
                },
            },
        },
        "Outputs": {
            "GroupName": {"Value": {"Ref": "Group"}},
            "GroupArn": {"Value": {"Fn::GetAtt": ["Group", "Arn"]}},
        },
    })


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::ResourceGroups::Group reads back through resource-groups' own
    GetGroup and GetGroupQuery with the declared name, ARN, description and tag query; deleting
    the stack removes the group, which resource-groups then refuses by name.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-resourcegroups-group.html
    """
    rg = ctx.client("resource-groups")
    cf = ctx.client("cloudformation")
    group_name = ctx.unique_name("sim2real-behav-rgq-")
    description = ctx.unique_name("sim2real-desc-")
    tag_value = ctx.unique_name("sim2real-tagval-")
    stack = ctx.unique_name("sim2real-behav-cfn-rgq-")

    stack_id = create_stack(ctx, cf, stack, _template(group_name, description, tag_value))
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack {stack!r} ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )

    outputs = stack_outputs(cf, stack_id)
    out_name, out_arn = outputs["GroupName"], outputs["GroupArn"]
    assert out_name == group_name, f"Ref resolved to {out_name!r}, expected the declared Name {group_name!r}"
    # Ref and GetAtt against an independent read: ListGroups' entry for the declared name.
    listed = [(g["GroupName"], g["GroupArn"]) for g in paginate(rg, "list_groups", "GroupIdentifiers")
              if g["GroupName"] == group_name]
    assert listed == [(out_name, out_arn)], (
        f"ListGroups lists {listed!r} under {group_name!r}; Ref/GetAtt are {(out_name, out_arn)!r}"
    )

    group = rg.get_group(Group=group_name)["Group"]
    assert group["Name"] == group_name, f"GetGroup Name {group['Name']!r} != {group_name!r}"
    assert group["GroupArn"] == out_arn, (
        f"GetGroup GroupArn {group['GroupArn']!r} != the GetAtt Arn output {out_arn!r}"
    )
    assert group["Description"] == description, (
        f"GetGroup Description {group['Description']!r} != the template's {description!r}"
    )

    group_query = rg.get_group_query(GroupName=group_name)["GroupQuery"]["ResourceQuery"]
    assert group_query["Type"] == "TAG_FILTERS_1_0", (
        f"GetGroupQuery Type {group_query['Type']!r} != 'TAG_FILTERS_1_0'"
    )
    want_query = {"ResourceTypeFilters": ["AWS::AllSupported"],
                  "TagFilters": [{"Key": "sim2real", "Values": [tag_value]}]}
    got_query = json.loads(group_query["Query"])
    assert got_query == want_query, f"GetGroupQuery Query {got_query!r} != {want_query!r}"

    delete_stack(cf, stack_id)
    stack_gone = ("ValidationError", _STACK_GONE.format(stack))
    expect_error(lambda: cf.describe_stacks(StackName=stack), *stack_gone)
    expect_error(lambda: rg.get_group(Group=group_name), *_GROUP_NOT_FOUND)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
