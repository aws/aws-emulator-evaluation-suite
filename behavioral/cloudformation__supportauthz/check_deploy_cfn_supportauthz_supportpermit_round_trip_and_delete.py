"""deploy-cfn-supportauthz-supportpermit-round-trip-and-delete."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-supportauthz-supportpermit-round-trip-and-delete"
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


def _template(permit_name, description, allow_before):
    key_props = {
        "Description": "sim2real signing key for a SupportAuthZ permit fidelity check",
        "KeySpec": "ECC_NIST_P384",
        "KeyUsage": "SIGN_VERIFY",
        "KeyPolicy": _key_policy(),
        "PendingWindowInDays": 7,
    }
    permit_props = {
        "Name": permit_name,
        "Description": description,
        "Permit": {
            "Actions": {"AllActions": {}},
            "Resources": {"Resources": [{"Fn::GetAtt": ["SigningKey", "Arn"]}]},
            "Conditions": [{"AllowBefore": allow_before}],
        },
        "SigningKeyInfo": {"KmsKey": {"Fn::GetAtt": ["SigningKey", "Arn"]}},
        "Tags": [{"Key": "sim2real-permit", "Value": permit_name}],
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
            "PermitId": {"Value": {"Fn::GetAtt": ["Permit", "PermitId"]}},
            "PermitStatus": {"Value": {"Fn::GetAtt": ["Permit", "Status"]}},
            "PermitCreatedAt": {"Value": {"Fn::GetAtt": ["Permit", "CreatedAt"]}},
            "KeyArn": {"Value": {"Fn::GetAtt": ["SigningKey", "Arn"]}},
        },
    })


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation SupportAuthZ support permit, signed by an in-stack KMS key, round-trips
    through SupportAuthZ's own API and is gone from it once the stack is deleted.
    """
    cf = ctx.client("cloudformation")
    authz = ctx.client("supportauthz")
    stack = ctx.unique_name("sim2real-authz-")
    permit_name = ctx.unique_name("sim2real")
    description = "sim2real support permit fidelity check"
    allow_before_dt = (datetime.now(timezone.utc) + timedelta(hours=1)).replace(microsecond=0)
    allow_before = allow_before_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    stack_id = create_stack(ctx, cf, stack, _template(permit_name, description, allow_before))
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    out = stack_outputs(cf, stack_id)

    # Ref against an independent read (ListSupportPermits, paginated), never describe-by-Ref then
    # compare back to the same Ref.
    permits = paginate(authz, "list_support_permits", "supportPermits")
    matches = [p for p in permits if p["name"] == permit_name]
    assert len(matches) == 1, f"ListSupportPermits found {len(matches)} named {permit_name!r}"
    listed = matches[0]
    assert out["PermitRef"] == listed["arn"], (
        f"Ref {out['PermitRef']!r} != ListSupportPermits arn {listed['arn']!r}"
    )
    assert out["PermitArn"] == listed["arn"], f"GetAtt Arn {out['PermitArn']!r} != {listed['arn']!r}"
    assert listed["status"] == "ACTIVE", f"listed status {listed['status']!r}, expected ACTIVE"

    got = authz.get_support_permit(supportPermitIdentifier=out["PermitRef"])
    assert got["arn"] == listed["arn"], f"GetSupportPermit arn {got['arn']!r} != {listed['arn']!r}"
    assert got["arn"].rsplit("/", 1)[-1] == out["PermitId"], (
        f"GetAtt PermitId {out['PermitId']!r} is not the resource segment of {got['arn']!r}"
    )
    created_at_attr = datetime.fromisoformat(out["PermitCreatedAt"].replace("Z", "+00:00"))
    assert created_at_attr == got["createdAt"].astimezone(timezone.utc), (
        f"GetAtt CreatedAt {out['PermitCreatedAt']!r} != GetSupportPermit createdAt {got['createdAt']!r}"
    )
    assert got["name"] == permit_name, f"GetSupportPermit name {got['name']!r} != {permit_name!r}"
    assert got["status"] == "ACTIVE", f"permit status {got['status']!r}, expected ACTIVE"
    assert out["PermitStatus"] == "ACTIVE", f"GetAtt Status {out['PermitStatus']!r} != ACTIVE"
    assert got["description"] == description, f"description {got['description']!r} != {description!r}"
    assert got["permit"]["resources"] == {"resources": [out["KeyArn"]]}, (
        f"permit.resources {got['permit']['resources']!r} != scoped to {out['KeyArn']!r}"
    )
    assert got["permit"]["actions"] == {"allActions": {}}, (
        f"permit.actions {got['permit']['actions']!r} != allActions"
    )
    conditions = got["permit"]["conditions"]
    assert len(conditions) == 1 and set(conditions[0]) == {"allowBefore"}, (
        f"permit.conditions {conditions!r}, expected a single allowBefore condition"
    )
    assert conditions[0]["allowBefore"].astimezone(timezone.utc) == allow_before_dt, (
        f"allowBefore {conditions[0]['allowBefore']!r} != {allow_before_dt!r}"
    )
    assert got["signingKeyInfo"] == {"kmsKey": out["KeyArn"]}, (
        f"signingKeyInfo {got['signingKeyInfo']!r} != {out['KeyArn']!r}"
    )

    permit_tags = authz.list_tags_for_resource(resourceArn=listed["arn"])["tags"]
    permit_tags = {k: v for k, v in permit_tags.items() if not k.startswith("aws:")}
    assert permit_tags == {"sim2real-permit": permit_name, "sim2real": stack}, (
        f"tags {permit_tags!r}"
    )

    delete_stack(cf, stack_id)
    until_raises(lambda: authz.get_support_permit(supportPermitIdentifier=out["PermitRef"]))
    gone = (
        "ResourceNotFoundException",
        f"A support permit with identifier {out['PermitRef']} could not be found",
    )
    expect_error(lambda: authz.get_support_permit(supportPermitIdentifier=out["PermitRef"]), *gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
