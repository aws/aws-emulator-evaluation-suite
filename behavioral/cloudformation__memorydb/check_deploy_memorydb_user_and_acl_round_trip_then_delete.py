"""deploy-memorydb-user-and-acl-round-trip-then-delete."""
from __future__ import annotations

import json
import secrets
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-memorydb-user-and-acl-round-trip-then-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "memorydb"]

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

_ACCESS_STRING = "on ~* &* +@all"


def _gen_password(length=24):
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _template(user_name, acl_name, with_acl=True):
    resources = {
        "User": {"Type": "AWS::MemoryDB::User", "Properties": {
            "UserName": user_name,
            "AccessString": _ACCESS_STRING,
            "AuthenticationMode": {"Type": "password", "Passwords": [{"Ref": "UserPassword"}]},
            "Tags": [{"Key": "sim2real-user", "Value": user_name}],
        }},
    }
    outputs = {
        "UserRef": {"Value": {"Ref": "User"}},
        "UserArn": {"Value": {"Fn::GetAtt": ["User", "Arn"]}},
    }
    if with_acl:
        resources["Acl"] = {"Type": "AWS::MemoryDB::ACL", "Properties": {
            "ACLName": acl_name,
            "UserNames": [{"Ref": "User"}],
        }}
        outputs["AclRef"] = {"Value": {"Ref": "Acl"}}
        outputs["AclArn"] = {"Value": {"Fn::GetAtt": ["Acl", "Arn"]}}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        # The password reaches the handler through a NoEcho parameter, never the template text.
        "Parameters": {"UserPassword": {"Type": "String", "NoEcho": True}},
        "Resources": resources,
        "Outputs": outputs,
    })


def _until(fn, want, timeout_s=90.0):
    """Poll ``fn()`` every 2 s until it equals ``want``; a final mismatch fails loudly."""
    deadline = time.monotonic() + timeout_s
    while True:
        got = fn()
        if got == want:
            return got
        if time.monotonic() > deadline:
            raise AssertionError(f"still {got!r} after {timeout_s:.0f}s, expected {want!r}")
        time.sleep(2)


def _own_named(client, op, key, name):
    rows = paginate(client, op, key)
    return [r for r in rows if r["Name"] == name]


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation MemoryDB user and ACL read back through MemoryDB as templated.

    An update dropping the ACL removes it while the user stays active, and deleting the stack
    removes the user.
    """
    cf = ctx.client("cloudformation")
    md = ctx.client("memorydb")
    stack = ctx.unique_name("sim2real-cfnmdb-ua-")
    user = ctx.unique_name("sim2real-cfnmdb-ua-user-")
    acl = ctx.unique_name("sim2real-cfnmdb-ua-acl-")
    params = [{"ParameterKey": "UserPassword", "ParameterValue": _gen_password()}]

    stack_id = create_stack(ctx, cf, stack, _template(user, acl), Parameters=params)
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    out = stack_outputs(cf, stack_id)
    partition = stack_id.split(":")[1]
    user_arn = f"arn:{partition}:memorydb:{ctx.region}:{ctx.account}:user/{user}"
    acl_arn = f"arn:{partition}:memorydb:{ctx.region}:{ctx.account}:acl/{acl}"

    # Ref against an independent read (ListAll via DescribeUsers/DescribeACLs), never a read
    # keyed by the Ref: the filter is our own generated name, known before the stack existed.
    listed_users = _own_named(md, "describe_users", "Users", user)
    assert len(listed_users) == 1, f"DescribeUsers found {listed_users!r} for name {user!r}"
    u = listed_users[0]
    assert u["Name"] == out["UserRef"], f"DescribeUsers Name {u['Name']!r} != Ref {out['UserRef']!r}"
    assert out["UserArn"] == u["ARN"] == user_arn, (
        f"GetAtt Arn {out['UserArn']!r}, DescribeUsers ARN {u['ARN']!r}, expected {user_arn!r}"
    )
    assert u["AccessString"] == _ACCESS_STRING, f"AccessString {u['AccessString']!r}"
    assert u["Authentication"]["Type"] == "password", f"Authentication {u['Authentication']!r}"
    assert u["Status"] == "active", f"user Status {u['Status']!r}, expected 'active'"
    user_tags = {t["Key"]: t["Value"] for t in md.list_tags(ResourceArn=user_arn)["TagList"]
                 if not t["Key"].startswith("aws:")}
    assert user_tags == {"sim2real": stack, "sim2real-user": user}, f"user tags {user_tags!r}"

    listed_acls = _own_named(md, "describe_acls", "ACLs", acl)
    assert len(listed_acls) == 1, f"DescribeACLs found {listed_acls!r} for name {acl!r}"
    a = listed_acls[0]
    assert a["Name"] == out["AclRef"], f"DescribeACLs Name {a['Name']!r} != Ref {out['AclRef']!r}"
    assert out["AclArn"] == a["ARN"] == acl_arn, (
        f"GetAtt Arn {out['AclArn']!r}, DescribeACLs ARN {a['ARN']!r}, expected {acl_arn!r}"
    )
    assert a["UserNames"] == [user], f"ACL UserNames {a['UserNames']!r} != {[user]!r}"
    assert a["Status"] == "active", f"acl Status {a['Status']!r}, expected 'active'"

    # Child before parent: drop only the ACL via a stack update; the user is unaffected.
    cf.update_stack(StackName=stack_id, TemplateBody=_template(user, acl, with_acl=False),
                    Parameters=params)
    status = wait_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"ACL-dropping update ended {status!r}"

    not_found = ("ACLNotFoundFault", f"ACL {acl} not found")
    expect_error(lambda: md.describe_acls(ACLName=acl), *not_found)
    remaining = _own_named(md, "describe_acls", "ACLs", acl)
    assert remaining == [], f"the dropped ACL is still listed: {remaining!r}"
    after_user = md.describe_users(UserName=user)["Users"][0]
    assert after_user["Status"] == "active", f"user Status after update {after_user['Status']!r}"
    assert after_user["AccessString"] == _ACCESS_STRING, (
        f"user AccessString after update {after_user['AccessString']!r}"
    )
    # ACLNames is eventually consistent after the ACL drops: bounded poll to convergence.
    _until(lambda: md.describe_users(UserName=user)["Users"][0]["ACLNames"], [])

    delete_stack(cf, stack_id)
    not_found_2 = ("UserNotFoundFault", f"User {user} not found.")
    expect_error(lambda: md.describe_users(UserName=user), *not_found_2)
    remaining_users = _own_named(md, "describe_users", "Users", user)
    assert remaining_users == [], f"the deleted user is still listed: {remaining_users!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
