"""deploy-ec2-ipam-pool-cidr-allocation-token-resolver-round-trip-then-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ec2-ipam-pool-cidr-allocation-token-resolver-round-trip-then-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2"]

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

def paginate_manual(fn, key, **kw):
    """Every item under ``key`` across all pages of an operation with no botocore paginator.

    ``describe_ipam_external_resource_verification_tokens`` declares a ``NextToken`` but botocore
    ships no paginator config for it, so this walks the token by hand.
    """
    out: list[dict] = []
    while True:
        page = fn(**kw)
        out.extend(page.get(key, []))
        token = page.get("NextToken")
        if not token:
            return out
        kw["NextToken"] = token


#: Fixed private blocks for the pool's provisioned CIDR and the allocation carved from it; a
#: fresh pool per run makes reuse across sibling runs safe.
_POOL_CIDR = "10.91.0.0/16"
_ALLOC_CIDR = "10.91.5.0/24"


def _template(description, prefix_list_name, with_cidr_and_allocation=True):
    resources = {
        "Ipam": {
            "Type": "AWS::EC2::IPAM",
            "Properties": {
                "Description": description,
                "Tier": "advanced",
                "OperatingRegions": [{"RegionName": {"Ref": "AWS::Region"}}],
            },
        },
        "Pool": {
            "Type": "AWS::EC2::IPAMPool",
            "Properties": {
                "IpamScopeId": {"Fn::GetAtt": ["Ipam", "PrivateDefaultScopeId"]},
                "AddressFamily": "ipv4",
                "Description": description,
            },
        },
        "Token": {
            "Type": "AWS::EC2::IpamExternalResourceVerificationToken",
            "Properties": {"IpamId": {"Fn::GetAtt": ["Ipam", "IpamId"]}},
        },
        "PrefixList": {
            "Type": "AWS::EC2::PrefixList",
            "Properties": {
                "PrefixListName": prefix_list_name, "AddressFamily": "IPv4", "MaxEntries": 1,
            },
        },
        "Resolver": {
            "Type": "AWS::EC2::IPAMPrefixListResolver",
            "Properties": {
                "IpamId": {"Fn::GetAtt": ["Ipam", "IpamId"]}, "AddressFamily": "ipv4",
            },
        },
        "ResolverTarget": {
            "Type": "AWS::EC2::IPAMPrefixListResolverTarget",
            "Properties": {
                "IpamPrefixListResolverId": {"Ref": "Resolver"},
                "PrefixListId": {"Ref": "PrefixList"},
                "PrefixListRegion": {"Ref": "AWS::Region"},
                "TrackLatestVersion": True,
            },
        },
    }
    outputs = {
        "IpamId": {"Value": {"Fn::GetAtt": ["Ipam", "IpamId"]}},
        "PoolRef": {"Value": {"Ref": "Pool"}},
        "TokenRef": {"Value": {"Ref": "Token"}},
        "TokenId": {
            "Value": {"Fn::GetAtt": ["Token", "IpamExternalResourceVerificationTokenId"]},
        },
        "ResolverRef": {"Value": {"Ref": "Resolver"}},
        "TargetRef": {"Value": {"Ref": "ResolverTarget"}},
        "PrefixListRef": {"Value": {"Ref": "PrefixList"}},
    }
    if with_cidr_and_allocation:
        resources["PoolCidr"] = {
            "Type": "AWS::EC2::IPAMPoolCidr",
            "Properties": {"IpamPoolId": {"Ref": "Pool"}, "Cidr": _POOL_CIDR},
        }
        resources["Allocation"] = {
            "Type": "AWS::EC2::IPAMAllocation",
            "DependsOn": "PoolCidr",
            "Properties": {
                "IpamPoolId": {"Ref": "Pool"}, "Cidr": _ALLOC_CIDR, "Description": description,
            },
        }
        outputs["PoolCidrRef"] = {"Value": {"Ref": "PoolCidr"}}
        outputs["PoolCidrId"] = {"Value": {"Fn::GetAtt": ["PoolCidr", "IpamPoolCidrId"]}}
        outputs["AllocationRef"] = {"Value": {"Ref": "Allocation"}}
        outputs["AllocationId"] = {
            "Value": {"Fn::GetAtt": ["Allocation", "IpamPoolAllocationId"]},
        }
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09", "Resources": resources, "Outputs": outputs,
    })


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """A CloudFormation IPAM pool CIDR, allocation, verification token, prefix-list resolver and
    resolver target read back through EC2; an update dropping the pool CIDR and allocation
    removes exactly those from the still-live pool, and deleting the stack removes the rest.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-ipampoolcidr.html
    """
    ec2 = ctx.client("ec2")
    cf = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-ec2ipamx-")
    prefix_list_name = ctx.unique_name("sim2real-ec2ipamx-pl-")

    stack_id = create_stack(ctx, cf, stack, _template(stack, prefix_list_name))
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    out = stack_outputs(cf, stack_id)

    pool_id = out["PoolRef"]
    ipam_id = out["IpamId"]

    pools = paginate(ec2, "describe_ipam_pools", "IpamPools",
                     Filters=[{"Name": "tag:sim2real", "Values": [stack]}])
    got = [(p["IpamPoolId"], p["AddressFamily"], p["Description"],
            {t["Key"]: t["Value"] for t in p["Tags"] if not t["Key"].startswith("aws:")})
           for p in pools]
    assert got == [(pool_id, "ipv4", stack, {"sim2real": stack})], f"pools by stack tag {got!r}"

    # ---- IPAMPoolCidr: Ref is "<pool>|<cidr-id>"; a read of the pool's own CIDR list. ----
    pool_ref, cidr_ref_id = out["PoolCidrRef"].split("|")
    assert (pool_ref, cidr_ref_id) == (pool_id, out["PoolCidrId"]), (
        f"PoolCidr Ref {out['PoolCidrRef']!r} does not decompose to (pool, GetAtt id) = "
        f"{(pool_id, out['PoolCidrId'])!r}"
    )
    cidrs = paginate(ec2, "get_ipam_pool_cidrs", "IpamPoolCidrs", IpamPoolId=pool_id)
    cidr_matches = [c for c in cidrs if c.get("IpamPoolCidrId") == cidr_ref_id]
    assert len(cidr_matches) == 1, f"pool {pool_id!r} cidrs by id {cidr_ref_id!r}: {cidr_matches!r}"
    assert (cidr_matches[0]["Cidr"], cidr_matches[0]["State"]) == (_POOL_CIDR, "provisioned"), (
        f"templated PoolCidr reads {cidr_matches[0]!r}, expected Cidr={_POOL_CIDR!r} provisioned"
    )

    # ---- IPAMAllocation: Ref is "<pool>|<alloc-id>|<cidr>"; a read keyed by the pool it owns. ----
    alloc_pool_ref, alloc_ref_id, alloc_ref_cidr = out["AllocationRef"].split("|")
    assert (alloc_pool_ref, alloc_ref_id, alloc_ref_cidr) == (
        pool_id, out["AllocationId"], _ALLOC_CIDR
    ), f"Allocation Ref {out['AllocationRef']!r} does not decompose as expected"
    allocs = paginate(ec2, "get_ipam_pool_allocations", "IpamPoolAllocations", IpamPoolId=pool_id)
    alloc_matches = [a for a in allocs if a.get("IpamPoolAllocationId") == out["AllocationId"]]
    assert len(alloc_matches) == 1, (
        f"pool {pool_id!r} allocations by id {out['AllocationId']!r}: {alloc_matches!r}"
    )
    assert (alloc_matches[0]["Cidr"], alloc_matches[0]["Description"]) == (_ALLOC_CIDR, stack), (
        f"templated Allocation reads {alloc_matches[0]!r}, expected Cidr={_ALLOC_CIDR!r} "
        f"Description={stack!r}"
    )

    # ---- IpamExternalResourceVerificationToken: Ref is the token's own Arn. ----
    tokens = paginate_manual(
        ec2.describe_ipam_external_resource_verification_tokens,
        "IpamExternalResourceVerificationTokens",
        Filters=[{"Name": "ipam-id", "Values": [ipam_id]}],
    )
    tok_matches = [t for t in tokens if t.get("IpamExternalResourceVerificationTokenId") ==
                   out["TokenId"]]
    assert len(tok_matches) == 1, (
        f"tokens for ipam {ipam_id!r}: {tokens!r}, expected one matching {out['TokenId']!r}"
    )
    assert tok_matches[0]["IpamExternalResourceVerificationTokenArn"] == out["TokenRef"], (
        f"token Ref {out['TokenRef']!r} != its own Arn "
        f"{tok_matches[0]['IpamExternalResourceVerificationTokenArn']!r}"
    )
    assert tok_matches[0]["Status"] == "valid", f"fresh token status {tok_matches[0]['Status']!r}"

    # ---- IPAMPrefixListResolver: Ref is the resolver's own id. ----
    resolvers = paginate(
        ec2, "describe_ipam_prefix_list_resolvers", "IpamPrefixListResolvers",
        Filters=[{"Name": "ipam-id", "Values": [ipam_id]}],
    )
    res_matches = [r for r in resolvers if r.get("IpamPrefixListResolverId") == out["ResolverRef"]]
    assert len(res_matches) == 1, (
        f"resolvers for ipam {ipam_id!r}: {resolvers!r}, expected one matching "
        f"{out['ResolverRef']!r}"
    )
    assert res_matches[0]["AddressFamily"] == "ipv4", f"resolver reads {res_matches[0]!r}"

    # ---- IPAMPrefixListResolverTarget: Ref is the target's own id; a read by the resolver it owns. ----
    targets = paginate(
        ec2, "describe_ipam_prefix_list_resolver_targets", "IpamPrefixListResolverTargets",
        IpamPrefixListResolverId=out["ResolverRef"],
    )
    tgt_matches = [t for t in targets if t.get("IpamPrefixListResolverTargetId") == out["TargetRef"]]
    assert len(tgt_matches) == 1, (
        f"targets for resolver {out['ResolverRef']!r}: {targets!r}, expected one matching "
        f"{out['TargetRef']!r}"
    )
    assert (tgt_matches[0]["PrefixListId"], tgt_matches[0]["TrackLatestVersion"]) == (
        out["PrefixListRef"], True
    ), f"templated ResolverTarget reads {tgt_matches[0]!r}"

    # ---- PrefixList: the resolver target's list, by its templated name. ----
    lists = paginate(ec2, "describe_managed_prefix_lists", "PrefixLists",
                     Filters=[{"Name": "prefix-list-name", "Values": [prefix_list_name]}])
    got = [(p["PrefixListId"], p["PrefixListName"], p["AddressFamily"], p["MaxEntries"])
           for p in lists]
    want = [(out["PrefixListRef"], prefix_list_name, "IPv4", 1)]
    assert got == want, f"DescribeManagedPrefixLists {got!r}, expected {want!r}"

    # ---- Child before parent: an update drops PoolCidr and Allocation while the pool lives on. ----
    cf.update_stack(StackName=stack_id, TemplateBody=_template(
        stack, prefix_list_name, with_cidr_and_allocation=False))
    status = wait_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"cidr/allocation-dropping update ended {status!r}"

    after_cidrs = paginate(ec2, "get_ipam_pool_cidrs", "IpamPoolCidrs", IpamPoolId=pool_id)
    after_cidr_matches = [c for c in after_cidrs if c.get("IpamPoolCidrId") == cidr_ref_id]
    assert len(after_cidr_matches) == 1, (
        f"pool {pool_id!r} cidrs by id {cidr_ref_id!r} after dropping PoolCidr: "
        f"{after_cidr_matches!r}"
    )
    assert after_cidr_matches[0]["State"] == "deprovisioned", (
        f"dropped PoolCidr tombstones as {after_cidr_matches[0]!r}, expected State deprovisioned"
    )

    refused = (
        "InvalidIpamPoolAllocationId.NotFound",
        f"The IPAM pool allocation ({out['AllocationId']}) does not exist.",
    )
    expect_error(
        lambda: ec2.get_ipam_pool_allocations(IpamPoolId=pool_id,
                                               IpamPoolAllocationId=out["AllocationId"]),
        *refused,
    )

    # The pool itself still answers: the two deletes above were the CHILDREN's, not the parent's.
    still_pool = ec2.describe_ipam_pools(IpamPoolIds=[pool_id])["IpamPools"]
    assert len(still_pool) == 1 and still_pool[0]["State"] == "create-complete", (
        f"the pool {pool_id!r} should still be live after dropping its children: {still_pool!r}"
    )

    # ---- Delete the stack, then prove the rest gone through EC2. ----
    delete_stack(cf, stack_id)

    refused = ("InvalidIpamPoolId.NotFound", f"The IPAM pool ({pool_id}) does not exist.")
    expect_error(lambda: ec2.describe_ipam_pools(IpamPoolIds=[pool_id]), *refused)

    refused = (
        "InvalidIpamExternalResourceVerificationTokenId.NotFound",
        f"The IPAM external resource verification token ({out['TokenId']}) does not exist.",
    )
    expect_error(
        lambda: ec2.describe_ipam_external_resource_verification_tokens(
            IpamExternalResourceVerificationTokenIds=[out["TokenId"]]),
        *refused,
    )

    refused = (
        "InvalidIpamPrefixListResolverId.NotFound",
        "The specified IPAM Prefix List Resolver does not exist.",
    )
    expect_error(
        lambda: ec2.describe_ipam_prefix_list_resolvers(
            IpamPrefixListResolverIds=[out["ResolverRef"]]),
        *refused,
    )

    refused = (
        "InvalidIpamPrefixListResolverTargetId.NotFound",
        "The specified IPAM Prefix List Resolver Target does not exist.",
    )
    expect_error(
        lambda: ec2.describe_ipam_prefix_list_resolver_targets(
            IpamPrefixListResolverTargetIds=[out["TargetRef"]]),
        *refused,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
