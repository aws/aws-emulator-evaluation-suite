"""deploy-elasticache-user-and-usergroup-round-trip-then-child-and-stack-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-elasticache-user-and-usergroup-round-trip-then-child-and-stack-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "elasticache"]

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

_USER_NOT_FOUND_MESSAGE = "User {} not found."
_GROUP_NOT_FOUND_MESSAGE = "User group {} not found."


def _template(user_id, group_id, with_group=True):
    resources = {
        "User": {
            "Type": "AWS::ElastiCache::User",
            "Properties": {
                "UserId": user_id,
                "UserName": "default",
                "Engine": "redis",
                "AccessString": "on ~* +@all",
                "AuthenticationMode": {"Type": "no-password-required"},
                "Tags": [{"Key": "sim2real-user", "Value": user_id}],
            },
        }
    }
    outputs = {
        "UserRef": {"Value": {"Ref": "User"}},
        "UserArn": {"Value": {"Fn::GetAtt": ["User", "Arn"]}},
    }
    if with_group:
        resources["UserGroup"] = {
            "Type": "AWS::ElastiCache::UserGroup",
            "Properties": {
                "UserGroupId": group_id,
                "Engine": "redis",
                "UserIds": [{"Ref": "User"}],
                "Tags": [{"Key": "sim2real-group", "Value": group_id}],
            },
        }
        outputs["UserGroupRef"] = {"Value": {"Ref": "UserGroup"}}
        outputs["UserGroupArn"] = {"Value": {"Fn::GetAtt": ["UserGroup", "Arn"]}}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": resources,
        "Outputs": outputs,
    })


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation ElastiCache User and UserGroup read back through ElastiCache, then the
    group is removed by a stack update before the whole stack, and each loss is independently
    proven."""
    cf = ctx.client("cloudformation")
    ec = ctx.client("elasticache")
    stack = ctx.unique_name("sim2real-cfnecu-")
    user_id = ctx.unique_name("sim2real-ecu-")
    group_id = ctx.unique_name("sim2real-ecg-")

    stack_id = create_stack(ctx, cf, stack, _template(user_id, group_id))
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    out = stack_outputs(cf, stack_id)
    partition = stack_id.split(":")[1]
    user_arn = f"arn:{partition}:elasticache:{ctx.region}:{ctx.account}:user:{user_id}"
    group_arn = f"arn:{partition}:elasticache:{ctx.region}:{ctx.account}:usergroup:{group_id}"

    # Ref against an independent read (an unfiltered list), never a read keyed by the Ref.
    users = paginate(ec, "describe_users", "Users")
    matched = [u for u in users if u["UserId"] == user_id]
    assert len(matched) == 1, f"ListUsers found {len(matched)} entries for Ref {out['UserRef']!r}"
    user = matched[0]
    assert out["UserRef"] == user_id, f"Ref {out['UserRef']!r} != template UserId {user_id!r}"
    # Read-only GetAtt == service value == documented format.
    assert (out["UserArn"], user["ARN"]) == (user_arn, user_arn), (
        f"GetAtt Arn {out['UserArn']!r}, ARN {user['ARN']!r}, expected {user_arn!r}"
    )
    got_user = {k: user.get(k) for k in ("UserName", "Engine", "AccessString", "Authentication")}
    want_user = {
        "UserName": "default", "Engine": "redis", "AccessString": "on ~* +@all",
        "Authentication": {"Type": "no-password"},
    }
    assert got_user == want_user, f"user read back {got_user!r}, expected {want_user!r}"
    user_tags = {t["Key"]: t["Value"] for t in ec.list_tags_for_resource(ResourceName=user_arn)["TagList"]}
    assert user_tags == {"sim2real": stack, "sim2real-user": user_id}, f"user tags {user_tags!r}"

    groups = paginate(ec, "describe_user_groups", "UserGroups")
    matchedg = [g for g in groups if g["UserGroupId"] == group_id]
    assert len(matchedg) == 1, (
        f"ListUserGroups found {len(matchedg)} entries for Ref {out['UserGroupRef']!r}"
    )
    group = matchedg[0]
    assert out["UserGroupRef"] == group_id, (
        f"Ref {out['UserGroupRef']!r} != template UserGroupId {group_id!r}"
    )
    assert (out["UserGroupArn"], group["ARN"]) == (group_arn, group_arn), (
        f"GetAtt Arn {out['UserGroupArn']!r}, ARN {group['ARN']!r}, expected {group_arn!r}"
    )
    got_group = {k: group.get(k) for k in ("Engine", "UserIds")}
    assert got_group == {"Engine": "redis", "UserIds": [user_id]}, f"group read back {got_group!r}"
    group_tags = {t["Key"]: t["Value"] for t in ec.list_tags_for_resource(ResourceName=group_arn)["TagList"]}
    assert group_tags == {"sim2real": stack, "sim2real-group": group_id}, f"group tags {group_tags!r}"

    # Child before parent: drop only the UserGroup. The user (parent) survives; the group (child)
    # is independently gone, proven through ElastiCache, before the stack itself is deleted.
    cf.update_stack(StackName=stack_id, TemplateBody=_template(user_id, group_id, with_group=False))
    status = wait_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"group-dropping update ended {status!r}"
    groups_after = paginate(ec, "describe_user_groups", "UserGroups")
    assert group_id not in {g["UserGroupId"] for g in groups_after}, (
        f"the dropped group {group_id!r} is still listed"
    )
    not_found = ("UserGroupNotFound", _GROUP_NOT_FOUND_MESSAGE.format(group_id))
    expect_error(lambda: ec.describe_user_groups(UserGroupId=group_id), *not_found)
    users_after = paginate(ec, "describe_users", "Users")
    survivor = [u for u in users_after if u["UserId"] == user_id]
    assert len(survivor) == 1 and survivor[0]["ARN"] == user_arn, (
        f"the user {user_id!r} did not survive the group-dropping update: {survivor!r}"
    )

    delete_stack(cf, stack_id)
    not_found_2 = ("UserNotFound", _USER_NOT_FOUND_MESSAGE.format(user_id))
    expect_error(lambda: ec.describe_users(UserId=user_id), *not_found_2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
