"""deploy-cfn-ec2-eip-getatt-publicip-feeds-route53-recordset-same-create."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-ec2-eip-getatt-publicip-feeds-route53-recordset-same-create"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2", "route53"]

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

def _template(zone_name: str, getatt_name: str, ref_name: str) -> str:
    t = [{"Key": "sim2real-check", "Value": zone_name}]
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Eip": {"Type": "AWS::EC2::EIP", "Properties": {"Domain": "vpc", "Tags": t}},
            "Zone": {
                "Type": "AWS::Route53::HostedZone",
                "Properties": {
                    "Name": zone_name,
                    "HostedZoneConfig": {"Comment": "sim2real"},
                    "HostedZoneTags": t,
                },
            },
            "RecordGetAtt": {
                "Type": "AWS::Route53::RecordSet",
                "Properties": {
                    "HostedZoneId": {"Ref": "Zone"},
                    "Name": getatt_name,
                    "Type": "A",
                    "TTL": "60",
                    "ResourceRecords": [{"Fn::GetAtt": ["Eip", "PublicIp"]}],
                },
            },
            "RecordRef": {
                "Type": "AWS::Route53::RecordSet",
                "Properties": {
                    "HostedZoneId": {"Ref": "Zone"},
                    "Name": ref_name,
                    "Type": "A",
                    "TTL": "60",
                    "ResourceRecords": [{"Ref": "Eip"}],
                },
            },
        },
    })


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::EC2::EIP's Fn::GetAtt PublicIp, consumed by an
    AWS::Route53::RecordSet's ResourceRecords created in the same stack, resolves to the
    address EC2 allocated rather than an empty list; Ref of the same EIP resolves identically.
    """
    ec2 = ctx.client("ec2")
    route53 = ctx.client("route53")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-cfneiprs-")
    zone_name = f"{ctx.unique_name('sim2real-cfneiprs-')}.test."
    getatt_name = f"getatt.{zone_name}"
    ref_name = f"ref.{zone_name}"

    stack_id = create_stack(ctx, cfn, stack, _template(zone_name, getatt_name, ref_name))

    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack {stack!r} ended {status!r}: "
        f"{decisive_rows(stack_events(cfn, stack_id))!r}"
    )

    resources = cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    physical = {r["LogicalResourceId"]: r["PhysicalResourceId"] for r in resources}
    # The EIP's PhysicalResourceId is its public IP (same value Ref returns); the allocation
    # itself is the independent ground truth that the Fn::GetAtt/Ref records are checked against.
    physical_ip, zone_id = physical["Eip"], physical["Zone"]

    addr = ec2.describe_addresses(PublicIps=[physical_ip])["Addresses"]
    assert addr, f"DescribeAddresses({physical_ip!r}) returned no addresses"
    alloc_id, public_ip = addr[0]["AllocationId"], addr[0]["PublicIp"]
    assert public_ip == physical_ip, (
        f"EC2's own PublicIp {public_ip!r} does not match the stack's PhysicalResourceId "
        f"{physical_ip!r}"
    )

    records = paginate(route53, "list_resource_record_sets", "ResourceRecordSets",
                        HostedZoneId=zone_id)
    by_name = {r["Name"]: r for r in records if r["Type"] == "A"}

    getatt_rec = by_name.get(getatt_name)
    assert getatt_rec is not None, (
        f"no A record named {getatt_name!r} among {sorted(by_name)!r}"
    )
    getatt_values = [rr["Value"] for rr in getatt_rec["ResourceRecords"]]
    assert getatt_values == [public_ip], (
        f"the GetAtt PublicIp record resolved to {getatt_values!r}, expected the allocated "
        f"address {[public_ip]!r}, not an empty list"
    )

    ref_rec = by_name.get(ref_name)
    assert ref_rec is not None, f"no A record named {ref_name!r} among {sorted(by_name)!r}"
    ref_values = [rr["Value"] for rr in ref_rec["ResourceRecords"]]
    assert ref_values == [public_ip], (
        f"the Ref record (positive control) resolved to {ref_values!r}, expected "
        f"{[public_ip]!r}"
    )

    delete_stack(cfn, stack_id)
    stack_gone = ("ValidationError", f"Stack with id {stack} does not exist")
    expect_error(lambda: cfn.describe_stacks(StackName=stack), *stack_gone)

    zone_gone = ("NoSuchHostedZone", f"No hosted zone found with ID: {zone_id}")
    expect_error(lambda: route53.get_hosted_zone(Id=zone_id), *zone_gone)

    addresses_gone = (
        "InvalidAllocationID.NotFound",
        f"The allocation ID '{alloc_id}' does not exist",
    )
    expect_error(lambda: ec2.describe_addresses(AllocationIds=[alloc_id]), *addresses_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
