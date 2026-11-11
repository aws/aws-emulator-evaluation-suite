"""deploy-cfn-rds-db-subnet-group-provisions-with-getatt-arn-and-lowercased-ref."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-rds-db-subnet-group-provisions-with-getatt-arn-and-lowercased-ref"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2", "rds"]

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


def _template(group_name: str, cidr: str, az_a: str, az_b: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Vpc": {
                "Type": "AWS::EC2::VPC",
                "Properties": {"CidrBlock": cidr},
            },
            "SubnetA": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {
                    "VpcId": {"Ref": "Vpc"},
                    "CidrBlock": {"Fn::Select": [0, {"Fn::Cidr": [cidr, 2, 8]}]},
                    "AvailabilityZone": az_a,
                },
            },
            "SubnetB": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {
                    "VpcId": {"Ref": "Vpc"},
                    "CidrBlock": {"Fn::Select": [1, {"Fn::Cidr": [cidr, 2, 8]}]},
                    "AvailabilityZone": az_b,
                },
            },
            "SubnetGroup": {
                "Type": "AWS::RDS::DBSubnetGroup",
                "Properties": {
                    "DBSubnetGroupName": group_name,
                    "DBSubnetGroupDescription": "sim2real db subnet group getatt check",
                    "SubnetIds": [{"Ref": "SubnetA"}, {"Ref": "SubnetB"}],
                },
            },
        },
        "Outputs": {
            "SubnetGroupNameOut": {"Value": {"Ref": "SubnetGroup"}},
            "SubnetGroupArnOut": {"Value": {"Fn::GetAtt": ["SubnetGroup", "DBSubnetGroupArn"]}},
            "VpcId": {"Value": {"Ref": "Vpc"}},
            "SubnetAId": {"Value": {"Ref": "SubnetA"}},
            "SubnetBId": {"Value": {"Ref": "SubnetB"}},
        },
    })


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A mixed-case DB subnet group deployed by CloudFormation reads back through RDS lower-cased,
    with the GetAtt ARN, its VPC and subnets as EC2 reports them, and is gone once the stack is
    deleted."""
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    rds = ctx.client("rds")

    azs = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    )
    assert len(azs) >= 2, f"region offers fewer than two available AZs: {azs!r}"
    az_a, az_b = azs[0], azs[1]

    mixed_case_name = ctx.unique_name("Sim2Real-CfnRds-Dbsg-")
    stack_name = ctx.unique_name("sim2real-cfnrds-stk-")

    stack_id = create_stack(ctx, cfn, stack_name,
                            _template(mixed_case_name, "10.91.0.0/16", az_a, az_b))
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", f"stack settled at {status!r}, expected CREATE_COMPLETE"

    outputs = stack_outputs(cfn, stack_id)
    lower_name = mixed_case_name.lower()
    assert outputs["SubnetGroupNameOut"] == lower_name, (
        f"Ref returned {outputs['SubnetGroupNameOut']!r}, expected the lower-cased "
        f"{lower_name!r} (the template supplied {mixed_case_name!r})"
    )

    groups = rds.describe_db_subnet_groups(DBSubnetGroupName=lower_name)["DBSubnetGroups"]
    assert len(groups) == 1, f"expected one subnet group named {lower_name!r}, got {groups!r}"
    group = groups[0]
    assert group["DBSubnetGroupName"] == lower_name, f"RDS name was {group['DBSubnetGroupName']!r}"
    assert group["DBSubnetGroupDescription"] == "sim2real db subnet group getatt check", (
        f"description was {group['DBSubnetGroupDescription']!r}"
    )
    assert group["VpcId"] == outputs["VpcId"], (
        f"RDS VpcId {group['VpcId']!r} != stack output {outputs['VpcId']!r}"
    )
    assert group["DBSubnetGroupArn"] == outputs["SubnetGroupArnOut"], (
        f"RDS Arn {group['DBSubnetGroupArn']!r} != stack GetAtt output {outputs['SubnetGroupArnOut']!r}"
    )
    rds_subnet_zones = {
        s["SubnetIdentifier"]: s["SubnetAvailabilityZone"]["Name"] for s in group["Subnets"]
    }
    assert rds_subnet_zones == {
        outputs["SubnetAId"]: az_a,
        outputs["SubnetBId"]: az_b,
    }, f"RDS subnet zones {rds_subnet_zones!r} did not match the stack's subnets and chosen AZs"

    vpcs = ec2.describe_vpcs(VpcIds=[outputs["VpcId"]])["Vpcs"]
    assert [v["CidrBlock"] for v in vpcs] == ["10.91.0.0/16"], (
        f"expected the VPC CidrBlock ['10.91.0.0/16'], got {[v['CidrBlock'] for v in vpcs]!r}"
    )
    subnets = ec2.describe_subnets(SubnetIds=[outputs["SubnetAId"], outputs["SubnetBId"]])["Subnets"]
    got_subnets = {
        s["SubnetId"]: (s["VpcId"], s["CidrBlock"], s["AvailabilityZone"]) for s in subnets
    }
    want_subnets = {
        outputs["SubnetAId"]: (outputs["VpcId"], "10.91.0.0/24", az_a),
        outputs["SubnetBId"]: (outputs["VpcId"], "10.91.1.0/24", az_b),
    }
    assert got_subnets == want_subnets, (
        f"expected subnets {want_subnets!r} through EC2, got {got_subnets!r}"
    )

    delete_stack(cfn, stack_id)
    group_gone = ("DBSubnetGroupNotFoundFault", f"DB Subnet group '{lower_name}' not found.")
    expect_error(lambda: rds.describe_db_subnet_groups(DBSubnetGroupName=lower_name), *group_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
