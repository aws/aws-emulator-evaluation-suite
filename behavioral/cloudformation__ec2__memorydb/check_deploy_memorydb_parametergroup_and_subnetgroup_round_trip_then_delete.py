"""deploy-memorydb-parametergroup-and-subnetgroup-round-trip-then-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-memorydb-parametergroup-and-subnetgroup-round-trip-then-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2", "memorydb"]

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

_FAMILY = "memorydb_valkey7"
_SUBNET_CIDR = "10.91.1.0/24"
_VPC_CIDR = "10.91.0.0/16"


def _usable_az(ec2) -> str:
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"])
    assert usable, "no available Availability Zone in this region"
    return usable[0]


def _template(pg_name, sg_name, az, description, parameters=None):
    pg_properties = {
        "ParameterGroupName": pg_name, "Family": _FAMILY, "Description": description,
        "Tags": [{"Key": "sim2real-pg", "Value": pg_name}],
    }
    if parameters:
        pg_properties["Parameters"] = parameters
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {
                "CidrBlock": _VPC_CIDR, "Tags": [{"Key": "sim2real-vpc", "Value": pg_name}],
            }},
            "Subnet": {"Type": "AWS::EC2::Subnet", "Properties": {
                "VpcId": {"Ref": "Vpc"}, "CidrBlock": _SUBNET_CIDR, "AvailabilityZone": az,
                "Tags": [{"Key": "sim2real-subnet", "Value": pg_name}],
            }},
            "ParameterGroup": {"Type": "AWS::MemoryDB::ParameterGroup", "Properties": pg_properties},
            "SubnetGroup": {"Type": "AWS::MemoryDB::SubnetGroup", "Properties": {
                "SubnetGroupName": sg_name, "Description": description,
                "SubnetIds": [{"Ref": "Subnet"}],
                "Tags": [{"Key": "sim2real-sg", "Value": sg_name}],
            }},
        },
        "Outputs": {
            "VpcId": {"Value": {"Ref": "Vpc"}},
            "SubnetId": {"Value": {"Ref": "Subnet"}},
            "ParameterGroupRef": {"Value": {"Ref": "ParameterGroup"}},
            "ParameterGroupArn": {"Value": {"Fn::GetAtt": ["ParameterGroup", "ARN"]}},
            "SubnetGroupRef": {"Value": {"Ref": "SubnetGroup"}},
            "SubnetGroupArn": {"Value": {"Fn::GetAtt": ["SubnetGroup", "ARN"]}},
        },
    })


def _own_tags(md, arn):
    """The resource's tags as sorted (key, value), without CloudFormation's aws: system tags."""
    return sorted((t["Key"], t["Value"]) for t in md.list_tags(ResourceArn=arn)["TagList"]
                  if not t["Key"].startswith("aws:"))


def _own_named(client, op, key, name):
    rows = paginate(client, op, key)
    return [r for r in rows if r["Name"] == name]


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation MemoryDB parameter group and subnet group read back through MemoryDB's
    own API, matching Ref, GetAtt ARN and every templated property and tag; an update setting
    Parameters changes the named parameter in place, and deleting the stack removes both."""
    cf = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    md = ctx.client("memorydb")
    stack = ctx.unique_name("sim2real-cfnmdb-pgsg-")
    pg_name = ctx.unique_name("sim2real-cfnmdb-pgsg-pg-")
    sg_name = ctx.unique_name("sim2real-cfnmdb-pgsg-sg-")
    description = "sim2real memorydb provisioning check"
    az = _usable_az(ec2)

    stack_id = create_stack(ctx, cf, stack, _template(pg_name, sg_name, az, description))
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    out = stack_outputs(cf, stack_id)
    partition = stack_id.split(":")[1]
    pg_arn = f"arn:{partition}:memorydb:{ctx.region}:{ctx.account}:parametergroup/{pg_name}"
    sg_arn = f"arn:{partition}:memorydb:{ctx.region}:{ctx.account}:subnetgroup/{sg_name}"

    # Ref against an independent read, never a read keyed by the Ref: the filter is our own
    # generated name, known before the stack existed.
    listed_pg = _own_named(md, "describe_parameter_groups", "ParameterGroups", pg_name)
    assert len(listed_pg) == 1, f"DescribeParameterGroups found {listed_pg!r} for {pg_name!r}"
    pg = listed_pg[0]
    assert pg["Name"] == out["ParameterGroupRef"], (
        f"DescribeParameterGroups Name {pg['Name']!r} != Ref {out['ParameterGroupRef']!r}"
    )
    assert out["ParameterGroupArn"] == pg["ARN"] == pg_arn, (
        f"GetAtt ARN {out['ParameterGroupArn']!r}, DescribeParameterGroups ARN {pg['ARN']!r}, "
        f"expected {pg_arn!r}"
    )
    assert (pg["Family"], pg["Description"]) == (_FAMILY, description), (
        f"ParameterGroup (Family, Description) {(pg['Family'], pg['Description'])!r} != "
        f"{(_FAMILY, description)!r}"
    )
    assert _own_tags(md, pg_arn) == [("sim2real", stack), ("sim2real-pg", pg_name)], (
        f"parameter group tags {_own_tags(md, pg_arn)!r}"
    )
    params = {p["Name"]: p.get("Value")
              for p in paginate(md, "describe_parameters", "Parameters",
                                ParameterGroupName=pg_name)}
    assert params.get("maxmemory-policy") == "noeviction", (
        f"default maxmemory-policy reads {params.get('maxmemory-policy')!r}, expected 'noeviction'"
    )

    # An update setting Parameters changes the value in place, on the same parameter group ARN.
    cf.update_stack(StackName=stack_id, TemplateBody=_template(
        pg_name, sg_name, az, description, parameters={"maxmemory-policy": "allkeys-lru"}
    ))
    status = wait_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"Parameters-setting update ended {status!r}"
    after_pg = paginate(md, "describe_parameter_groups", "ParameterGroups",
                        ParameterGroupName=pg_name)[0]
    assert after_pg["ARN"] == pg_arn, f"ParameterGroup ARN changed after update: {after_pg['ARN']!r}"
    after_params = {p["Name"]: p.get("Value")
                    for p in paginate(md, "describe_parameters", "Parameters",
                                      ParameterGroupName=pg_name)}
    assert after_params.get("maxmemory-policy") == "allkeys-lru", (
        f"maxmemory-policy after update reads {after_params.get('maxmemory-policy')!r}, "
        f"expected 'allkeys-lru'"
    )

    listed_sg = _own_named(md, "describe_subnet_groups", "SubnetGroups", sg_name)
    assert len(listed_sg) == 1, f"DescribeSubnetGroups found {listed_sg!r} for {sg_name!r}"
    sg = listed_sg[0]
    assert sg["Name"] == out["SubnetGroupRef"], (
        f"DescribeSubnetGroups Name {sg['Name']!r} != Ref {out['SubnetGroupRef']!r}"
    )
    assert out["SubnetGroupArn"] == sg["ARN"] == sg_arn, (
        f"GetAtt ARN {out['SubnetGroupArn']!r}, DescribeSubnetGroups ARN {sg['ARN']!r}, "
        f"expected {sg_arn!r}"
    )
    assert sg["Description"] == description, f"SubnetGroup Description {sg['Description']!r}"
    assert _own_tags(md, sg_arn) == [("sim2real", stack), ("sim2real-sg", sg_name)], (
        f"subnet group tags {_own_tags(md, sg_arn)!r}"
    )
    assert sg["VpcId"] == out["VpcId"], f"SubnetGroup VpcId {sg['VpcId']!r} != {out['VpcId']!r}"
    subnet_ids = sorted(s["Identifier"] for s in sg["Subnets"])
    assert subnet_ids == [out["SubnetId"]], (
        f"SubnetGroup Subnets {subnet_ids!r} != {[out['SubnetId']]!r}"
    )

    delete_stack(cf, stack_id)
    refused = ("ParameterGroupNotFoundFault", "Parameter Group not found.")
    expect_error(lambda: md.describe_parameter_groups(ParameterGroupName=pg_name), *refused)
    refused = ("SubnetGroupNotFoundFault", f"Subnet group {sg_name} not found.")
    expect_error(lambda: md.describe_subnet_groups(SubnetGroupName=sg_name), *refused)
    assert _own_named(md, "describe_parameter_groups", "ParameterGroups", pg_name) == [], (
        "the deleted parameter group is still listed"
    )
    assert _own_named(md, "describe_subnet_groups", "SubnetGroups", sg_name) == [], (
        "the deleted subnet group is still listed"
    )

    refused = ("InvalidVpcID.NotFound", f"The vpc ID '{out['VpcId']}' does not exist")
    expect_error(lambda: ec2.describe_vpcs(VpcIds=[out["VpcId"]]), *refused)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
