"""deploy-resourcegroups-group-duplicate-name-rejected-leaving-the-original."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-resourcegroups-group-duplicate-name-rejected-leaving-the-original"
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


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


def validation_rows(cf, stack_id):
    """Sorted ``(logical id, ValidationName, Status, FailureMode, Reason, Path)`` rows."""
    return sorted(
        (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
         e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
        for e in paginate(cf, "describe_events", "OperationEvents", StackName=stack_id)
        if e.get("EventType") == "VALIDATION_ERROR"
    )


# ---- Check-specific: the template, then run(). ----

_VALIDATION_REASON = (
    "Validation failed with 1 error(s). Call DescribeEvents to retrieve the full list of "
    "issues with resource and property details, resolve each error, then retry the operation."
)


def _resource_query(tag_value: str) -> dict:
    return {
        "Type": "TAG_FILTERS_1_0",
        "Query": {"ResourceTypeFilters": ["AWS::AllSupported"],
                  "TagFilters": [{"Key": "sim2real", "Values": [tag_value]}]},
    }


def _template(group_name: str, description: str, tag_value: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Group": {
                "Type": "AWS::ResourceGroups::Group",
                "Properties": {
                    "Name": group_name,
                    "Description": description,
                    "ResourceQuery": _resource_query(tag_value),
                },
            },
        },
        "Outputs": {"GroupArn": {"Value": {"Fn::GetAtt": ["Group", "Arn"]}}},
    })


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second stack creating an AWS::ResourceGroups::Group with a name resource-groups
    already holds fails CloudFormation's own pre-create validation before any resource is
    touched, and leaves the first stack's group untouched.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-resourcegroups-group.html
    """
    cf = ctx.client("cloudformation")
    rg = ctx.client("resource-groups")
    group_name = ctx.unique_name("sim2real-behav-dupg-")
    description_a = ctx.unique_name("sim2real-desc-a-")
    description_b = ctx.unique_name("sim2real-desc-b-")
    tag_value = ctx.unique_name("sim2real-tagval-")
    stack_a = ctx.unique_name("sim2real-behav-cfn-dupg-a-")
    stack_b = ctx.unique_name("sim2real-behav-cfn-dupg-b-")

    stack_a_id = create_stack(ctx, cf, stack_a, _template(group_name, description_a, tag_value))
    status = wait_stack(cf, stack_a_id)
    assert status == "CREATE_COMPLETE", f"stack A create ended {status!r}, expected CREATE_COMPLETE"

    # Positive control: stack A's group reads back with every property the template set, and
    # its server-minted GroupArn identifies it across stack B's attempt.
    group_arn = stack_outputs(cf, stack_a_id)["GroupArn"]
    before = rg.get_group(Group=group_name)["Group"]
    got = (before["Name"], before["GroupArn"], before["Description"])
    want = (group_name, group_arn, description_a)
    assert got == want, f"stack A's group (Name, GroupArn, Description) is {got!r}, expected {want!r}"
    query = rg.get_group_query(Group=group_name)["GroupQuery"]["ResourceQuery"]
    want_query = _resource_query(tag_value)
    got_query = {"Type": query["Type"], "Query": json.loads(query["Query"])}
    assert got_query == want_query, f"stack A's group query is {got_query!r}, expected {want_query!r}"

    stack_b_id = create_stack(ctx, cf, stack_b, _template(group_name, description_b, tag_value))
    status = wait_stack(cf, stack_b_id)
    assert status == "ROLLBACK_COMPLETE", f"stack B create ended {status!r}, expected ROLLBACK_COMPLETE"

    reason = failed_reason(stack_events(cf, stack_b_id), stack_b)
    assert reason == _VALIDATION_REASON, f"CREATE_FAILED reason {reason!r} != {_VALIDATION_REASON!r}"

    found = validation_rows(cf, stack_b_id)
    want_errors = [(
        "Group", "NAME_CONFLICT_VALIDATION", "FAILED", "FAIL",
        f"Resource of type 'AWS::ResourceGroups::Group' with identifier '{group_name}' already exists.",
        "/Resources/Group",
    )]
    assert found == want_errors, (
        f"validation errors of stack B's create: expected {want_errors!r}, got {found!r}"
    )

    # CloudFormation's own validation refuses the duplicate name before attempting to create
    # anything: no resource for this stack was ever provisioned.
    resources = cf.list_stack_resources(StackName=stack_b_id)["StackResourceSummaries"]
    assert resources == [], f"expected no resources provisioned for the rejected stack, got {resources!r}"

    # Stack A's group is the same group, unharmed by stack B's failed attempt.
    after = rg.get_group(Group=group_name)["Group"]
    got_after = (after["GroupArn"], after["Description"])
    assert got_after == (group_arn, description_a), (
        f"stack A's group (GroupArn, Description) changed to {got_after!r}, expected "
        f"{(group_arn, description_a)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
