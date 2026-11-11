"""cfn-user-pool-user-to-group-attachment-proves-and-removes-membership."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "cfn-user-pool-user-to-group-attachment-proves-and-removes-membership"
GROUP = "deploy"
SERVICES = ["cloudformation", "cognito-idp"]

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


# ---- Check-specific: the template, then run(). ----

def _template(*, with_attachment: bool, pool_name: str, username: str, group_name: str) -> str:
    resources = {
        "Pool": {"Type": "AWS::Cognito::UserPool", "Properties": {"UserPoolName": pool_name}},
        "User": {
            "Type": "AWS::Cognito::UserPoolUser",
            "Properties": {
                "UserPoolId": {"Ref": "Pool"},
                "Username": username,
                "MessageAction": "SUPPRESS",
            },
        },
        "Group": {
            "Type": "AWS::Cognito::UserPoolGroup",
            "Properties": {"UserPoolId": {"Ref": "Pool"}, "GroupName": group_name},
        },
    }
    if with_attachment:
        resources["Attach"] = {
            "Type": "AWS::Cognito::UserPoolUserToGroupAttachment",
            "DependsOn": ["User", "Group"],
            "Properties": {
                "UserPoolId": {"Ref": "Pool"},
                "Username": username,
                "GroupName": group_name,
            },
        }
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": resources,
        "Outputs": {
            "PoolRef": {"Value": {"Ref": "Pool"}},
            **({"AttachRef": {"Value": {"Ref": "Attach"}}} if with_attachment else {}),
        },
    })


def _groups_of(cognito, pool_id, username):
    return [g["GroupName"] for g in paginate(cognito, "admin_list_groups_for_user", "Groups",
                                             UserPoolId=pool_id, Username=username)]


def _identities(cognito, pool_id, username, group_name):
    """Server-minted identities of the user and group the update must leave untouched."""
    return (cognito.admin_get_user(UserPoolId=pool_id, Username=username)["UserCreateDate"],
            cognito.get_group(UserPoolId=pool_id, GroupName=group_name)["Group"]["CreationDate"])


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation UserPoolUserToGroupAttachment creates the membership, and an update removes it.

    Its Ref is the listed pool Id|GroupName|Username and AdminListGroupsForUser shows the group;
    the update drops the membership while the same user and group remain.
    """
    cfn, cognito = ctx.client("cloudformation"), ctx.client("cognito-idp")
    pool_name = ctx.unique_name("sim2real-behav-cogu2gpool-")
    names = {"pool_name": pool_name, "username": "sim2real-u2g-user",
             "group_name": "sim2real-u2g-group"}

    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-cogu2gstack-"),
                            _template(with_attachment=True, **names))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    pools = [p["Id"] for p in paginate(cognito, "list_user_pools", "UserPools", MaxResults=60)
             if p["Name"] == pool_name]
    assert pools == [out["PoolRef"]], f"user pools named {pool_name!r}: {pools!r}"
    pool_id = pools[0]
    want_ref = f"{pool_id}|{names['group_name']}|{names['username']}"
    assert out["AttachRef"] == want_ref, f"attachment Ref {out['AttachRef']!r}, expected {want_ref!r}"
    groups = _groups_of(cognito, pool_id, names["username"])
    assert groups == [names["group_name"]], f"AdminListGroupsForUser {groups!r}"
    before = _identities(cognito, pool_id, names["username"], names["group_name"])

    cfn.update_stack(StackName=stack_id, TemplateBody=_template(with_attachment=False, **names))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"attachment-dropping update ended {status!r}"
    groups = _groups_of(cognito, pool_id, names["username"])
    assert groups == [], f"AdminListGroupsForUser after the update {groups!r}"
    after = _identities(cognito, pool_id, names["username"], names["group_name"])
    assert after == before, f"the user or group was replaced across the update: {before!r} -> {after!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
