"""cfn-iam-user-group-policies-and-virtual-mfa-device-read-back-then-removed-on-delete."""
from __future__ import annotations

import json
import time
import urllib.parse

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-iam-user-group-policies-and-virtual-mfa-device-read-back-then-removed-on-delete"
GROUP = "resource-existence"
SERVICES = ["cloudformation", "iam"]

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

def _wait_absent(fn, *, timeout_s=120.0, interval_s=2.0):
    """Poll fn() (a predicate) until it returns True."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = fn()
        if last:
            return
        time.sleep(interval_s)
    raise AssertionError(f"condition not met after {timeout_s}s (last check returned {last!r})")


def _doc(doc):
    """IAM echoes PolicyDocument as a URL-encoded JSON string on some calls, a dict on others."""
    return doc if isinstance(doc, dict) else json.loads(urllib.parse.unquote(doc))


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed User, Group, their inline UserPolicy/GroupPolicy and a
    VirtualMFADevice assigned to the user are all real at IAM; deleting the stack removes every
    one of them from IAM, not just from CFN.
    """
    cfn = ctx.client("cloudformation")
    iam = ctx.client("iam")
    stack_name = ctx.unique_name("sim2real-behav-cfn-iamug-")
    user_name = ctx.unique_name("sim2real-behav-user-")
    group_name = ctx.unique_name("sim2real-behav-group-")
    user_policy_name = ctx.unique_name("sim2real-behav-up-")
    group_policy_name = ctx.unique_name("sim2real-behav-gp-")
    mfa_device_name = ctx.unique_name("sim2real-behav-mfa-")
    bucket_name = ctx.unique_name("sim2real-behav-bucket-").lower()

    def docs(s3_arn):
        """(user policy, group policy) documents, each S3 ARN built by ``s3_arn(suffix)``."""
        return (
            {"Version": "2012-10-17",
             "Statement": [{"Effect": "Allow", "Action": "s3:GetObject",
                            "Resource": s3_arn(f"{bucket_name}/*")}]},
            {"Version": "2012-10-17",
             "Statement": [{"Effect": "Allow", "Action": "s3:ListBucket",
                            "Resource": s3_arn(bucket_name)}]},
        )

    user_tpl, group_tpl = docs(lambda suffix: {"Fn::Sub": f"arn:${{AWS::Partition}}:s3:::{suffix}"})

    template = json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "User": {
                "Type": "AWS::IAM::User",
                "Properties": {"UserName": user_name, "Path": "/"},
            },
            "UserPolicy": {
                "Type": "AWS::IAM::UserPolicy",
                "Properties": {
                    "UserName": {"Ref": "User"},
                    "PolicyName": user_policy_name,
                    "PolicyDocument": user_tpl,
                },
            },
            "Group": {
                "Type": "AWS::IAM::Group",
                "Properties": {"GroupName": group_name},
            },
            "GroupPolicy": {
                "Type": "AWS::IAM::GroupPolicy",
                "Properties": {
                    "GroupName": {"Ref": "Group"},
                    "PolicyName": group_policy_name,
                    "PolicyDocument": group_tpl,
                },
            },
            "MfaDevice": {
                "Type": "AWS::IAM::VirtualMFADevice",
                "Properties": {
                    "VirtualMfaDeviceName": mfa_device_name,
                    "Users": [{"Ref": "User"}],
                    "Path": "/",
                },
            },
        },
        "Outputs": {
            "UserRef": {"Value": {"Ref": "User"}},
            "UserArn": {"Value": {"Fn::GetAtt": ["User", "Arn"]}},
            "GroupRef": {"Value": {"Ref": "Group"}},
            "GroupArn": {"Value": {"Fn::GetAtt": ["Group", "Arn"]}},
            "MfaSerial": {"Value": {"Ref": "MfaDevice"}},
        },
    })

    stack_id = create_stack(ctx, cfn, stack_name, template, Capabilities=["CAPABILITY_NAMED_IAM"])
    created = wait_stack(cfn, stack_id)
    assert created == "CREATE_COMPLETE", (
        f"expected CREATE_COMPLETE, got {created!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    partition = stack_id.split(":")[1]
    user_doc, group_doc = docs(lambda suffix: f"arn:{partition}:s3:::{suffix}")

    outputs = stack_outputs(cfn, stack_id)

    # ---- AWS::IAM::User and AWS::IAM::Group: Ref is the name the template declared.
    refs = (outputs["UserRef"], outputs["GroupRef"])
    assert refs == (user_name, group_name), (
        f"Ref of (User, Group) {refs!r}, expected {(user_name, group_name)!r}"
    )

    # ---- AWS::IAM::User: GetUser's Arn matches the GetAtt output.
    user = iam.get_user(UserName=user_name)["User"]
    assert user["Path"] == "/", f"expected Path '/', got {user['Path']!r}"
    assert outputs["UserArn"] == user["Arn"], (
        f"GetAtt User.Arn was {outputs['UserArn']!r}, IAM's own Arn is {user['Arn']!r}"
    )

    # ---- AWS::IAM::UserPolicy: scoped to the user, by role/user + policy name.
    up = iam.get_user_policy(UserName=user_name, PolicyName=user_policy_name)
    assert _doc(up["PolicyDocument"]) == user_doc, (
        f"expected the declared UserPolicy document {user_doc!r}, got {_doc(up['PolicyDocument'])!r}"
    )

    # ---- AWS::IAM::Group: Ref is the GroupName; GetGroup's Arn matches the GetAtt output.
    group = iam.get_group(GroupName=group_name)["Group"]
    assert outputs["GroupArn"] == group["Arn"], (
        f"GetAtt Group.Arn was {outputs['GroupArn']!r}, IAM's own Arn is {group['Arn']!r}"
    )

    # ---- AWS::IAM::GroupPolicy: scoped to the group, by group + policy name.
    gp = iam.get_group_policy(GroupName=group_name, PolicyName=group_policy_name)
    assert _doc(gp["PolicyDocument"]) == group_doc, (
        f"expected the declared GroupPolicy document {group_doc!r}, got {_doc(gp['PolicyDocument'])!r}"
    )

    # ---- AWS::IAM::VirtualMFADevice: Ref is the device's serial number; it shows up assigned
    # to the user it names.
    mfa_serial = outputs["MfaSerial"]
    want_serial = f"arn:{partition}:iam::{ctx.account}:mfa/{mfa_device_name}"
    assert mfa_serial == want_serial, (
        f"VirtualMFADevice Ref {mfa_serial!r}, expected {want_serial!r}"
    )
    devices = paginate(iam, "list_virtual_mfa_devices", "VirtualMFADevices", AssignmentStatus="Any")
    mine = [d for d in devices if d["SerialNumber"] == mfa_serial]
    assert len(mine) == 1, f"expected exactly one virtual MFA device {mfa_serial!r}, found {mine!r}"
    assert mine[0].get("User", {}).get("UserName") == user_name, (
        f"expected the device assigned to {user_name!r}, got {mine[0].get('User')!r}"
    )

    delete_stack(cfn, stack_id)

    # The physical deletes may lag DELETE_COMPLETE: poll each read to its refusal, then grade it.
    user_gone = ("NoSuchEntity", f"The user with name {user_name} cannot be found.")
    until_raises(lambda: iam.get_user(UserName=user_name), timeout_s=120.0)
    expect_error(lambda: iam.get_user(UserName=user_name), *user_gone)

    group_gone = ("NoSuchEntity", f"The group with name {group_name} cannot be found.")
    until_raises(lambda: iam.get_group(GroupName=group_name), timeout_s=120.0)
    expect_error(lambda: iam.get_group(GroupName=group_name), *group_gone)

    def _mfa_gone():
        found = paginate(iam, "list_virtual_mfa_devices", "VirtualMFADevices",
                         AssignmentStatus="Any")
        return not any(d["SerialNumber"] == mfa_serial for d in found)

    _wait_absent(_mfa_gone, timeout_s=120.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
