"""cfn-deploy-neptune-db-subnet-group-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-neptune-db-subnet-group-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2", "neptune"]

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

_VPC_CIDR = "10.120.0.0/16"
_SUBNET_CIDRS = ("10.120.1.0/24", "10.120.2.0/24")


def _template(group_name: str, azs: tuple[str, str], tag_value: str) -> str:
    t = [{"Key": "sim2real-check", "Value": tag_value}]
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": _VPC_CIDR, "Tags": t}},
            "SubnetA": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {"VpcId": {"Ref": "Vpc"}, "CidrBlock": _SUBNET_CIDRS[0],
                                "AvailabilityZone": azs[0], "Tags": t},
            },
            "SubnetB": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {"VpcId": {"Ref": "Vpc"}, "CidrBlock": _SUBNET_CIDRS[1],
                                "AvailabilityZone": azs[1], "Tags": t},
            },
            "SubnetGroup": {
                "Type": "AWS::Neptune::DBSubnetGroup",
                "Properties": {
                    "DBSubnetGroupName": group_name,
                    "DBSubnetGroupDescription": "sim2real neptune db subnet group",
                    "SubnetIds": [{"Ref": "SubnetA"}, {"Ref": "SubnetB"}],
                    "Tags": t,
                },
            },
        },
        "Outputs": {
            "VpcId": {"Value": {"Ref": "Vpc"}},
            "SubnetAId": {"Value": {"Ref": "SubnetA"}},
            "SubnetBId": {"Value": {"Ref": "SubnetB"}},
            "SubnetGroupName": {"Value": {"Ref": "SubnetGroup"}},
        },
    })


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::Neptune::DBSubnetGroup reads back through Neptune's own
    DescribeDBSubnetGroups with the declared description, tags, VPC and exact subnet set; deleting
    the stack removes it, which Neptune then refuses by name.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-neptune-dbsubnetgroup.html
    """
    ec2 = ctx.client("ec2")
    nep = ctx.client("neptune")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-nep-sng-")
    group_name = ctx.unique_name("sim2real-nep-subnetgrp-")

    zones = sorted(
        z["ZoneName"] for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    )
    assert len(zones) >= 2, f"region {ctx.region!r} offers fewer than 2 available AZs: {zones!r}"
    azs = (zones[0], zones[1])

    stack_id = create_stack(ctx, cfn, stack, _template(group_name, azs, CHECK))

    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"stack {stack!r} ended {status!r}, expected CREATE_COMPLETE"

    outputs = stack_outputs(cfn, stack_id)
    vpc_id = outputs["VpcId"]
    subnet_ids = {outputs["SubnetAId"], outputs["SubnetBId"]}
    group_ref = outputs["SubnetGroupName"]
    assert group_ref == group_name, (
        f"expected SubnetGroup's Ref to equal its name {group_name!r}, got {group_ref!r}"
    )

    vpcs = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"]
    assert [v["CidrBlock"] for v in vpcs] == [_VPC_CIDR], (
        f"expected VPC {vpc_id!r} with CidrBlock {_VPC_CIDR!r}, EC2 reports {vpcs!r}"
    )
    subnets = ec2.describe_subnets(SubnetIds=sorted(subnet_ids))["Subnets"]
    got_subnets = {(s["SubnetId"], s["VpcId"], s["CidrBlock"], s["AvailabilityZone"])
                   for s in subnets}
    want_subnets = {
        (outputs["SubnetAId"], vpc_id, _SUBNET_CIDRS[0], azs[0]),
        (outputs["SubnetBId"], vpc_id, _SUBNET_CIDRS[1], azs[1]),
    }
    assert got_subnets == want_subnets, (
        f"expected subnets {want_subnets!r}, EC2 reports {got_subnets!r}"
    )

    groups = nep.describe_db_subnet_groups(DBSubnetGroupName=group_ref)["DBSubnetGroups"]
    assert len(groups) == 1, (
        f"DescribeDBSubnetGroups({group_ref!r}) returned {len(groups)} groups, expected 1"
    )
    g = groups[0]
    assert g["DBSubnetGroupName"] == group_ref, (
        f"expected DBSubnetGroupName {group_ref!r}, Neptune reports {g['DBSubnetGroupName']!r}"
    )
    assert g["DBSubnetGroupDescription"] == "sim2real neptune db subnet group", (
        f"expected the declared description, Neptune reports {g['DBSubnetGroupDescription']!r}"
    )
    assert g["VpcId"] == vpc_id, f"expected VpcId {vpc_id!r}, Neptune reports {g['VpcId']!r}"
    got_subnet_ids = {s["SubnetIdentifier"] for s in g["Subnets"]}
    assert got_subnet_ids == subnet_ids, (
        f"expected subnet set {subnet_ids!r}, Neptune reports {got_subnet_ids!r}"
    )
    # The template's tag plus the aws:cloudformation:* tags CloudFormation adds to the group;
    # the stack's own sim2real tag is not asserted here.
    tag_list = nep.list_tags_for_resource(ResourceName=g["DBSubnetGroupArn"])["TagList"]
    want_tags = sorted([
        {"Key": "sim2real-check", "Value": CHECK},
        {"Key": "aws:cloudformation:stack-name", "Value": stack},
        {"Key": "aws:cloudformation:logical-id", "Value": "SubnetGroup"},
        {"Key": "aws:cloudformation:stack-id", "Value": stack_id},
    ], key=lambda t: t["Key"])
    got_tags = sorted((t for t in tag_list if t["Key"] != "sim2real"), key=lambda t: t["Key"])
    assert got_tags == want_tags, (
        f"expected the template's Tags {want_tags!r}, Neptune reports {tag_list!r}"
    )

    delete_stack(cfn, stack_id)
    stack_gone = ("ValidationError", f"Stack with id {stack} does not exist")
    expect_error(lambda: cfn.describe_stacks(StackName=stack), *stack_gone)

    db_subnet_groups_gone = (
        "DBSubnetGroupNotFoundFault",
        f"DB Subnet group '{group_ref}' not found.",
    )
    expect_error(
        lambda: nep.describe_db_subnet_groups(DBSubnetGroupName=group_ref),
        *db_subnet_groups_gone,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
