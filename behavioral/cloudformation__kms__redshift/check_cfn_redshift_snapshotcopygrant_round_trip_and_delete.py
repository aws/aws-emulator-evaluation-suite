"""cfn-redshift-snapshotcopygrant-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-redshift-snapshotcopygrant-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "kms", "redshift"]

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

_KEY_DESCRIPTION = "sim2real behavioral snapshot copy grant key"


def _template(grant_name: str, kms_key_id) -> str:
    """A stack-owned KMS key and a snapshot copy grant on ``kms_key_id``."""
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Key": {
                "Type": "AWS::KMS::Key",
                "Properties": {
                    "Description": _KEY_DESCRIPTION,
                    "PendingWindowInDays": 7,
                    "KeyPolicy": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Sid": "AllowAccountFullAccess",
                            "Effect": "Allow",
                            "Principal": {"AWS": {
                                "Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"}},
                            "Action": "kms:*",
                            "Resource": "*",
                        }],
                    },
                },
            },
            "Grant": {
                "Type": "AWS::Redshift::SnapshotCopyGrant",
                "Properties": {"SnapshotCopyGrantName": grant_name, "KmsKeyId": kms_key_id},
            },
        },
        "Outputs": {
            "GrantRef": {"Value": {"Ref": "Grant"}},
            "GrantArn": {"Value": {"Fn::GetAtt": ["Grant", "Arn"]}},
            "KeyId": {"Value": {"Ref": "Key"}},
            "KeyArn": {"Value": {"Fn::GetAtt": ["Key", "Arn"]}},
        },
    })


def _grants(rs, name: str) -> list[dict]:
    return paginate(rs, "describe_snapshot_copy_grants", "SnapshotCopyGrants",
                    SnapshotCopyGrantName=name)


def _not_found(name: str) -> tuple[str, str]:
    return "SnapshotCopyGrantNotFoundFault", f"Snapshot copy grant '{name}' not found."


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::Redshift::SnapshotCopyGrant reads back naming the stack's KMS key.

    Ref and the Arn GetAtt are the documented grant ARN, Redshift lists the grant on the key KMS
    reads back, and the stack delete removes the grant and schedules the key for deletion.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-redshift-snapshotcopygrant.html
    """
    rs = ctx.client("redshift")
    kms = ctx.client("kms")
    cfn = ctx.client("cloudformation")
    grant_name = ctx.unique_name("sim2real-cfnrs-scg-")

    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-cfnrs-scg-"),
                            _template(grant_name, {"Ref": "Key"}))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    partition = stack_id.split(":")[1]
    want_arn = f"arn:{partition}:redshift:{ctx.region}:{ctx.account}:snapshotcopygrant:{grant_name}"
    assert (out["GrantRef"], out["GrantArn"]) == (want_arn, want_arn), f"Ref/GetAtt {out!r}"
    grants = [(g["SnapshotCopyGrantName"], g["KmsKeyId"]) for g in _grants(rs, grant_name)]
    assert grants == [(grant_name, out["KeyArn"])], f"Redshift lists {grants!r}"
    key = kms.describe_key(KeyId=out["KeyId"])["KeyMetadata"]
    got = (key["Arn"], key["Description"], key["KeyState"])
    assert got == (out["KeyArn"], _KEY_DESCRIPTION, "Enabled"), f"KMS key reads {got!r}"

    delete_stack(cfn, stack_id)
    expect_error(lambda: rs.describe_snapshot_copy_grants(SnapshotCopyGrantName=grant_name),
                 *_not_found(grant_name))
    state = kms.describe_key(KeyId=out["KeyId"])["KeyMetadata"]["KeyState"]
    assert state == "PendingDeletion", f"the stack's key is {state!r} after the delete"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
