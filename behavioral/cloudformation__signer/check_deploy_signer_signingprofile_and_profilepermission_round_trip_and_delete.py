"""deploy-signer-signingprofile-and-profilepermission-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-signer-signingprofile-and-profilepermission-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "signer"]

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

_PLATFORM_ID = "AWSLambda-SHA384-ECDSA"
_VALIDITY_VALUE = 135
_VALIDITY_TYPE = "DAYS"
_ACTION = "signer:StartSigningJob"
_STATEMENT_ID = "AllowStartSigningJob"


def _template(profile_name: str, action: str, with_permission=True) -> str:
    resources = {"Profile": {
        "Type": "AWS::Signer::SigningProfile",
        "Properties": {
            "ProfileName": profile_name,
            "PlatformId": _PLATFORM_ID,
            "SignatureValidityPeriod": {"Type": _VALIDITY_TYPE, "Value": _VALIDITY_VALUE},
            "Tags": [{"Key": "sim2real-profile", "Value": profile_name}],
        },
    }}
    outputs = {
        "ProfileArn": {"Value": {"Ref": "Profile"}},
        "ProfileName": {"Value": {"Fn::GetAtt": ["Profile", "ProfileName"]}},
        "ProfileVersion": {"Value": {"Fn::GetAtt": ["Profile", "ProfileVersion"]}},
        "ProfileVersionArn": {"Value": {"Fn::GetAtt": ["Profile", "ProfileVersionArn"]}},
    }
    if with_permission:
        resources["Permission"] = {
            "Type": "AWS::Signer::ProfilePermission",
            "Properties": {
                "ProfileName": {"Fn::GetAtt": ["Profile", "ProfileName"]},
                "Action": action,
                "Principal": {"Ref": "AWS::AccountId"},
                "StatementId": _STATEMENT_ID,
            },
        }
        outputs["PermissionRef"] = {"Value": {"Ref": "Permission"}}
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources,
                       "Outputs": outputs})


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation Signer SigningProfile and ProfilePermission read back through Signer with
    the template's values and tags; an update dropping the permission removes its policy while the
    profile stays Active, and deleting the stack cancels the profile (Signer's tombstone).
    """
    signer = ctx.client("signer")
    cfn = ctx.client("cloudformation")
    profile_name = ctx.unique_name("sim2real_sigprof_")
    stack = ctx.unique_name("sim2real-sigprof-")

    stack_id = create_stack(ctx, cfn, stack, _template(profile_name, _ACTION))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)
    assert outputs["PermissionRef"] == f"{_STATEMENT_ID}|{profile_name}", (
        f"Ref(Permission) {outputs['PermissionRef']!r} is not 'StatementId|ProfileName'"
    )
    profile = signer.get_signing_profile(profileName=profile_name)
    got = {
        "ProfileArn": profile["arn"], "ProfileName": profile["profileName"],
        "ProfileVersion": profile["profileVersion"],
        "ProfileVersionArn": profile["profileVersionArn"],
    }
    want = {k: outputs[k] for k in got}
    assert got == want and want["ProfileName"] == profile_name, (
        f"Signer reads {got!r}, Ref/GetAtt {want!r}, declared name {profile_name!r}"
    )
    got = (profile["platformId"], profile["signatureValidityPeriod"], profile["status"])
    want = (_PLATFORM_ID, {"value": _VALIDITY_VALUE, "type": _VALIDITY_TYPE}, "Active")
    assert got == want, f"profile (platform, validity, status) {got!r} != {want!r}"
    got = {k: v for k, v in profile.get("tags", {}).items() if not k.startswith("aws:")}
    assert got == {"sim2real": stack, "sim2real-profile": profile_name}, f"profile tags {got!r}"
    perms = [(p["statementId"], p["action"], p["principal"]) for p in
             signer.list_profile_permissions(profileName=profile_name)["permissions"]]
    assert perms == [(_STATEMENT_ID, _ACTION, ctx.account)], f"profile permissions {perms!r}"

    # Child first: the update drops the permission; its policy is gone while the profile is Active.
    cfn.update_stack(StackName=stack_id,
                     TemplateBody=_template(profile_name, _ACTION, with_permission=False))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"permission-dropping update ended {status!r}"
    gone = ("ResourceNotFoundException", f"No policies associated with profile {profile_name}")
    expect_error(lambda: signer.list_profile_permissions(profileName=profile_name), *gone)
    still = signer.get_signing_profile(profileName=profile_name)
    got = (still["profileVersionArn"], still["status"])
    assert got == (outputs["ProfileVersionArn"], "Active"), f"profile after the update {got!r}"

    delete_stack(cfn, stack_id)
    canceled = signer.get_signing_profile(profileName=profile_name)
    assert canceled["status"] == "Canceled", (
        f"profile status {canceled['status']!r} after the stack delete, expected 'Canceled'"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
