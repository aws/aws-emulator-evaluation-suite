"""deploy-ram-resource-share-permission-round-trip-then-delete."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-ram-resource-share-permission-round-trip-then-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "ram"]

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


def manual_paginate(fn, key, **kw):
    """Every item under ``key`` across all pages of a non-paginatable ``fn``, via ``nextToken``."""
    items = []
    token = None
    while True:
        resp = fn(nextToken=token, **kw) if token else fn(**kw)
        items.extend(resp.get(key, []))
        token = resp.get("nextToken")
        if not token:
            return items


_POLICY_TEMPLATE = {"Effect": "Allow", "Action": ["ssm:DescribeDocument", "ssm:GetDocument"]}


def _template(share_name, perm_name, allow_external):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Permission": {
                "Type": "AWS::RAM::Permission",
                "Properties": {
                    "Name": perm_name,
                    "ResourceType": "ssm:Document",
                    "PolicyTemplate": _POLICY_TEMPLATE,
                    "Tags": [{"Key": "sim2real-ram-pm", "Value": perm_name}],
                },
            },
            "Share": {
                "Type": "AWS::RAM::ResourceShare",
                "Properties": {
                    "Name": share_name,
                    "AllowExternalPrincipals": allow_external,
                    "Tags": [{"Key": "sim2real-ram-sh", "Value": share_name}],
                },
            },
            "PermissionAssociation": {
                "Type": "AWS::RAM::PermissionAssociation",
                "Properties": {
                    "ResourceShareArn": {"Ref": "Share"},
                    "PermissionArn": {"Ref": "Permission"},
                    "Replace": True,
                },
            },
        },
        "Outputs": {
            "ShareRef": {"Value": {"Ref": "Share"}},
            "ShareArn": {"Value": {"Fn::GetAtt": ["Share", "Arn"]}},
            "PermRef": {"Value": {"Ref": "Permission"}},
            "PermArn": {"Value": {"Fn::GetAtt": ["Permission", "Arn"]}},
        },
    })


def _find_share(ram, name):
    """``get_resource_shares`` filtered to our own share name, paginated."""
    pages = paginate(ram, "get_resource_shares", "resourceShares",
                      resourceOwner="SELF", name=name)
    return [s for s in pages if s["name"] == name]


def _find_permission(ram, name):
    """``list_permissions`` scoped to ``ssm:Document``, paginated by hand, filtered to our name."""
    pages = manual_paginate(ram.list_permissions, "permissions", resourceType="ssm:Document")
    return [p for p in pages if p["name"] == name]


def _find_permission_association(ram, permission_arn):
    """``list_permission_associations`` for ``permission_arn``, paginated by hand."""
    return manual_paginate(ram.list_permission_associations, "permissions",
                            permissionArn=permission_arn)


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation RAM resource share, customer-managed permission and their association
    round-trip through RAM, an in-place share update persists, and stack delete tombstones both.
    """
    cf = ctx.client("cloudformation")
    ram = ctx.client("ram")
    stack = ctx.unique_name("sim2real-cfnram-")
    share_name = ctx.unique_name("sim2real-cfnram-sh-")
    perm_name = ctx.unique_name("sim2real-cfnram-pm-")

    stack_id = create_stack(ctx, cf, stack, _template(share_name, perm_name, False))
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    out = stack_outputs(cf, stack_id)
    assert out["ShareRef"] == out["ShareArn"], (
        f"Ref {out['ShareRef']!r} != GetAtt Arn {out['ShareArn']!r} for a RAM resource share"
    )
    assert out["PermRef"] == out["PermArn"], (
        f"Ref {out['PermRef']!r} != GetAtt Arn {out['PermArn']!r} for a RAM permission"
    )

    # Independent reads (never keyed by the Ref itself): list by the name the template declared.
    shares = _find_share(ram, share_name)
    assert [s["resourceShareArn"] for s in shares] == [out["ShareRef"]], (
        f"get_resource_shares by name found {shares!r} for Ref {out['ShareRef']!r}"
    )
    share = shares[0]
    assert (share["status"], share["allowExternalPrincipals"]) == ("ACTIVE", False), (
        f"share read back {share!r}"
    )
    creation_time = share["creationTime"]
    share_tags = {t["key"]: t["value"] for t in share.get("tags", [])
                  if not t["key"].startswith("aws:")}
    assert share_tags == {"sim2real": stack, "sim2real-ram-sh": share_name}, (
        f"share tags {share_tags!r}"
    )

    perms = _find_permission(ram, perm_name)
    assert [p["arn"] for p in perms] == [out["PermRef"]], (
        f"list_permissions by name found {perms!r} for Ref {out['PermRef']!r}"
    )
    got_perm = ram.get_permission(permissionArn=perms[0]["arn"])["permission"]
    assert (got_perm["resourceType"], got_perm["permissionType"]) == ("ssm:Document",
                                                                       "CUSTOMER_MANAGED"), (
        f"permission read back {got_perm!r}"
    )
    assert json.loads(got_perm["permission"]) == _POLICY_TEMPLATE, (
        f"policy template read back {got_perm['permission']!r}, expected {_POLICY_TEMPLATE!r}"
    )

    perm_tags = {t["key"]: t["value"] for t in perms[0].get("tags", [])
                 if not t["key"].startswith("aws:")}
    assert perm_tags == {"sim2real": stack, "sim2real-ram-pm": perm_name}, (
        f"permission tags {perm_tags!r}"
    )

    assoc_rows = _find_permission_association(ram, out["PermRef"])
    assert [(a["resourceShareArn"], a["status"]) for a in assoc_rows] == [
        (out["ShareRef"], "ASSOCIATED")
    ], f"permission association read back {assoc_rows!r}"

    # In-place update: flip the one mutable property, same resource (server-minted CreationTime).
    cf.update_stack(StackName=stack_id, TemplateBody=_template(share_name, perm_name, True))
    status = wait_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"update ended {status!r}"
    updated = _find_share(ram, share_name)[0]
    assert (updated["resourceShareArn"], updated["creationTime"], updated["allowExternalPrincipals"]) == (
        out["ShareRef"], creation_time, True
    ), f"after the update the share reads {updated!r}"

    delete_stack(cf, stack_id)

    deleted_shares = _find_share(ram, share_name)
    assert [(s["resourceShareArn"], s["status"]) for s in deleted_shares] == [
        (out["ShareRef"], "DELETED")
    ], f"the deleted share is listed as {deleted_shares!r}"
    deleted_perm = ram.get_permission(permissionArn=out["PermRef"])["permission"]
    assert deleted_perm["status"] == "DELETED", f"the deleted permission reads {deleted_perm!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
