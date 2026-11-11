"""deploy-elasticache-subnetgroup-name-lowercased-round-trip-then-stack-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-elasticache-subnetgroup-name-lowercased-round-trip-then-stack-delete"
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

_NOT_FOUND_MESSAGE = "Cache subnet group {} not found."


def _template(mixed_case_name, description, subnet_ids):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "SubnetGroup": {
                "Type": "AWS::ElastiCache::SubnetGroup",
                "Properties": {
                    "CacheSubnetGroupName": mixed_case_name,
                    "Description": description,
                    "SubnetIds": subnet_ids,
                    "Tags": [{"Key": "sim2real-subnetgroup", "Value": mixed_case_name}],
                },
            }
        },
        "Outputs": {"SubnetGroupRef": {"Value": {"Ref": "SubnetGroup"}}},
    })


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation ElastiCache SubnetGroup is lower-cased to its Ref and reads back through
    ElastiCache; deleting the stack removes it."""
    cf = ctx.client("cloudformation")
    ec = ctx.client("elasticache")
    net = ctx.network()
    stack = ctx.unique_name("sim2real-cfnecsng-")
    requested_name = ctx.unique_name("Sim2Real-ECSNG-")
    description = f"sim2real subnet group for {stack}"
    subnet_ids = sorted(net.subnet_ids[:2])

    stack_id = create_stack(ctx, cf, stack, _template(requested_name, description, subnet_ids))
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    out = stack_outputs(cf, stack_id)
    assert out["SubnetGroupRef"] == requested_name.lower(), (
        f"Ref {out['SubnetGroupRef']!r} != lower-cased name {requested_name.lower()!r}"
    )
    assert out["SubnetGroupRef"] != requested_name, (
        "the requested name was already lower-case; this run proves nothing about lower-casing"
    )

    # Ref against an independent read (an unfiltered list), never a read keyed by the Ref.
    groups = paginate(ec, "describe_cache_subnet_groups", "CacheSubnetGroups")
    matched = [g for g in groups if g["CacheSubnetGroupName"] == requested_name.lower()]
    assert len(matched) == 1, (
        f"ListCacheSubnetGroups found {len(matched)} entries for Ref {out['SubnetGroupRef']!r}"
    )
    group = matched[0]
    assert group["CacheSubnetGroupDescription"] == description, (
        f"description {group['CacheSubnetGroupDescription']!r} != {description!r}"
    )
    assert group["VpcId"] == net.vpc_id, f"VpcId {group['VpcId']!r} != {net.vpc_id!r}"
    got_subnets = sorted(s["SubnetIdentifier"] for s in group["Subnets"])
    assert got_subnets == subnet_ids, f"subnets {got_subnets!r} != template's {subnet_ids!r}"
    group_tags = {
        t["Key"]: t["Value"]
        for t in ec.list_tags_for_resource(ResourceName=group["ARN"])["TagList"]
    }
    assert group_tags == {"sim2real": stack, "sim2real-subnetgroup": requested_name}, (
        f"tags {group_tags!r}"
    )

    delete_stack(cf, stack_id)
    not_found = ("CacheSubnetGroupNotFoundFault", _NOT_FOUND_MESSAGE.format(out["SubnetGroupRef"]))
    expect_error(
        lambda: ec.describe_cache_subnet_groups(CacheSubnetGroupName=out["SubnetGroupRef"]),
        *not_found,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
