"""deploy-cfn-supportauthz-supportpermit-invalid-name-rejected."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-supportauthz-supportpermit-invalid-name-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "supportauthz"]

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


def validation_rows(cf, stack_id):
    """Sorted ``(logical id, ValidationName, Status, FailureMode, Reason, Path)`` rows."""
    return sorted(
        (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
         e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
        for e in paginate(cf, "describe_events", "OperationEvents", StackName=stack_id)
        if e.get("EventType") == "VALIDATION_ERROR"
    )


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

def _key_policy():
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "EnableRootPermissions",
                "Effect": "Allow",
                "Principal": {"AWS": {"Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"}},
                "Action": "kms:*",
                "Resource": "*",
            },
            {
                "Sid": "AllowSupportAuthZSigning",
                "Effect": "Allow",
                "Principal": {"Service": "supportauthz.amazonaws.com"},
                "Action": ["kms:Sign", "kms:GetPublicKey", "kms:DescribeKey"],
                "Resource": "*",
                "Condition": {"StringEquals": {"aws:SourceAccount": {"Ref": "AWS::AccountId"}}},
            },
        ],
    }


def _template(permit_name, allow_before):
    key_props = {
        "Description": "sim2real signing key for a SupportAuthZ permit fidelity check",
        "KeySpec": "ECC_NIST_P384",
        "KeyUsage": "SIGN_VERIFY",
        "KeyPolicy": _key_policy(),
        "PendingWindowInDays": 7,
    }
    permit_props = {
        "Name": permit_name,
        "Description": "sim2real support permit fidelity check",
        "Permit": {
            "Actions": {"AllActions": {}},
            "Resources": {"Resources": [{"Fn::GetAtt": ["SigningKey", "Arn"]}]},
            "Conditions": [{"AllowBefore": allow_before}],
        },
        "SigningKeyInfo": {"KmsKey": {"Fn::GetAtt": ["SigningKey", "Arn"]}},
    }
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "SigningKey": {"Type": "AWS::KMS::Key", "Properties": key_props},
            "Permit": {"Type": "AWS::SupportAuthZ::SupportPermit", "Properties": permit_props},
        },
        "Outputs": {
            "PermitRef": {"Value": {"Ref": "Permit"}},
            "PermitArn": {"Value": {"Fn::GetAtt": ["Permit", "Arn"]}},
        },
    })


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation support permit whose Name holds a hyphen fails early validation and rolls
    back, while the same template with an alphanumeric name deploys.
    """
    cf = ctx.client("cloudformation")
    authz = ctx.client("supportauthz")
    allow_before = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    good_name = ctx.unique_name("sim2real")
    bad_name = ctx.unique_name("sim2real") + "-bad"

    # Positive control: same template, the one property given a VALID value (never dropped).
    good_id = create_stack(ctx, cf, ctx.unique_name("sim2real-authzgood-"),
                           _template(good_name, allow_before))
    status = wait_stack(cf, good_id)
    assert status == "CREATE_COMPLETE", f"control stack ended {status!r}"
    good_out = stack_outputs(cf, good_id)
    listed = [p["arn"] for p in paginate(authz, "list_support_permits", "supportPermits")
              if p["name"] == good_name]
    assert listed == [good_out["PermitRef"]], f"ListSupportPermits found {listed!r}"
    got = authz.get_support_permit(supportPermitIdentifier=good_name)
    got = (got["name"], got["description"], got["status"])
    assert got == (good_name, "sim2real support permit fidelity check", "ACTIVE"), (
        f"control permit reads {got!r}"
    )

    bad_id = create_stack(ctx, cf, ctx.unique_name("sim2real-authzbad-"),
                          _template(bad_name, allow_before))
    status = wait_stack(cf, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    rows = validation_rows(cf, bad_id)
    assert rows == [
        ("Permit", "PROPERTY_VALIDATION", "FAILED", "FAIL",
         f"Property value [{bad_name}] does not match pattern: ^[a-zA-Z0-9]{{1,256}}$",
         "/Resources/Permit/Properties/Name"),
    ], f"validation rows {rows!r}"

    # Rollback absence through SupportAuthZ, by the name the permit would have, BEFORE this
    # check's own delete.
    permits = paginate(authz, "list_support_permits", "supportPermits")
    assert bad_name not in {p["name"] for p in permits}, (
        f"the rolled-back permit {bad_name!r} is listed"
    )
    gone = (
        "ResourceNotFoundException",
        f"A support permit with identifier {bad_name} could not be found",
    )
    expect_error(lambda: authz.get_support_permit(supportPermitIdentifier=bad_name), *gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
