"""deploy-docdb-dbclusterparametergroup-and-dbsubnetgroup-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-docdb-dbclusterparametergroup-and-dbsubnetgroup-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "docdb"]

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


_VPC_CIDR = "10.121.0.0/16"
_FAMILY = "docdb5.0"
_PARAM_NAME = "audit_logs"
_PARAM_VALUE = "enabled"
_DESCRIPTION = "sim2real docdb cluster parameter group"
_SUBNET_DESCRIPTION = "sim2real docdb subnet group"


def _template(tag_value: str, param_group_name: str, subnet_group_name: str) -> str:
    t = [{"Key": "sim2real-res", "Value": tag_value}]
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": _VPC_CIDR}},
            "SubnetA": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {"VpcId": {"Ref": "Vpc"}, "CidrBlock": "10.121.1.0/24",
                                "AvailabilityZone": {"Fn::Select": [0, {"Fn::GetAZs": ""}]}},
            },
            "SubnetB": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {"VpcId": {"Ref": "Vpc"}, "CidrBlock": "10.121.2.0/24",
                                "AvailabilityZone": {"Fn::Select": [1, {"Fn::GetAZs": ""}]}},
            },
            "ClusterParameterGroup": {
                "Type": "AWS::DocDB::DBClusterParameterGroup",
                "Properties": {
                    "Name": param_group_name,
                    "Description": _DESCRIPTION,
                    "Family": _FAMILY,
                    "Parameters": {_PARAM_NAME: _PARAM_VALUE},
                    "Tags": t,
                },
            },
            "SubnetGroup": {
                "Type": "AWS::DocDB::DBSubnetGroup",
                "Properties": {
                    "DBSubnetGroupName": subnet_group_name,
                    "DBSubnetGroupDescription": _SUBNET_DESCRIPTION,
                    "SubnetIds": [{"Ref": "SubnetA"}, {"Ref": "SubnetB"}],
                    "Tags": t,
                },
            },
        },
        "Outputs": {
            "VpcId": {"Value": {"Ref": "Vpc"}},
            "SubnetAId": {"Value": {"Ref": "SubnetA"}},
            "SubnetBId": {"Value": {"Ref": "SubnetB"}},
            "ParameterGroupName": {"Value": {"Ref": "ClusterParameterGroup"}},
            "SubnetGroupName": {"Value": {"Ref": "SubnetGroup"}},
        },
    })


def _user_tags(docdb, arn: str) -> dict:
    tag_list = docdb.list_tags_for_resource(ResourceName=arn)["TagList"]
    return {t["Key"]: t["Value"] for t in tag_list if not t["Key"].startswith("aws:")}


@tags("axis:happy-path", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A stack's AWS::DocDB::DBClusterParameterGroup and AWS::DocDB::DBSubnetGroup read back
    through DocDB's own API with the template's Family, Description, parameter value and
    subnet ids; deleting the stack removes both, which DocDB then refuses by name.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-docdb-dbclusterparametergroup.html
    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-docdb-dbsubnetgroup.html
    """
    docdb = ctx.client("docdb")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-docdbgrp-")
    tag_value = ctx.unique_name("sim2real-docdbgrp-res-")
    want_tags = {"sim2real": stack, "sim2real-res": tag_value}
    param_group_name = ctx.unique_name("sim2real-docdbgrp-pg-")
    subnet_group_name = ctx.unique_name("sim2real-docdbgrp-sng-")

    stack_id = create_stack(ctx, cfn, stack,
                            _template(tag_value, param_group_name, subnet_group_name))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )

    outputs = stack_outputs(cfn, stack_id)
    vpc_id = outputs["VpcId"]
    subnet_ids = {outputs["SubnetAId"], outputs["SubnetBId"]}

    # Each Ref against an independent listing by the templated name, never a read by the Ref.
    groups = [g for g in paginate(docdb, "describe_db_cluster_parameter_groups",
                                  "DBClusterParameterGroups")
              if g["DBClusterParameterGroupName"] == param_group_name]
    assert len(groups) == 1, (
        f"DescribeDBClusterParameterGroups named {param_group_name!r}: {groups!r}"
    )
    group = groups[0]
    assert outputs["ParameterGroupName"] == param_group_name, (
        f"ClusterParameterGroup Ref {outputs['ParameterGroupName']!r}, listed {param_group_name!r}"
    )
    assert group["DBParameterGroupFamily"] == _FAMILY, (
        f"expected family {_FAMILY!r}, DocDB reports {group['DBParameterGroupFamily']!r}"
    )
    assert group["Description"] == _DESCRIPTION, (
        f"expected description {_DESCRIPTION!r}, DocDB reports {group['Description']!r}"
    )

    group_tags = _user_tags(docdb, group["DBClusterParameterGroupArn"])
    assert group_tags == want_tags, f"parameter group tags {group_tags!r}, expected {want_tags!r}"

    params = paginate(docdb, "describe_db_cluster_parameters", "Parameters",
                      DBClusterParameterGroupName=param_group_name)
    by_name = {p["ParameterName"]: p for p in params}
    assert _PARAM_NAME in by_name, (
        f"expected parameter {_PARAM_NAME!r} in the group, DocDB returned "
        f"{sorted(by_name)!r}"
    )
    assert by_name[_PARAM_NAME]["ParameterValue"] == _PARAM_VALUE, (
        f"expected {_PARAM_NAME!r}={_PARAM_VALUE!r}, DocDB reports "
        f"{by_name[_PARAM_NAME]['ParameterValue']!r}"
    )

    subnet_groups = [g for g in paginate(docdb, "describe_db_subnet_groups", "DBSubnetGroups")
                     if g["DBSubnetGroupName"] == subnet_group_name]
    assert len(subnet_groups) == 1, (
        f"DescribeDBSubnetGroups named {subnet_group_name!r}: {subnet_groups!r}"
    )
    sg = subnet_groups[0]
    assert outputs["SubnetGroupName"] == subnet_group_name, (
        f"SubnetGroup Ref {outputs['SubnetGroupName']!r}, listed {subnet_group_name!r}"
    )
    assert sg["DBSubnetGroupDescription"] == _SUBNET_DESCRIPTION, (
        f"expected description {_SUBNET_DESCRIPTION!r}, DocDB reports "
        f"{sg['DBSubnetGroupDescription']!r}"
    )
    assert sg["VpcId"] == vpc_id, f"expected VpcId {vpc_id!r}, DocDB reports {sg['VpcId']!r}"
    got_subnet_ids = {s["SubnetIdentifier"] for s in sg["Subnets"]}
    assert got_subnet_ids == subnet_ids, (
        f"expected subnet ids {subnet_ids!r}, DocDB reports {got_subnet_ids!r}"
    )

    sg_tags = _user_tags(docdb, sg["DBSubnetGroupArn"])
    assert sg_tags == want_tags, f"subnet group tags {sg_tags!r}, expected {want_tags!r}"

    delete_stack(cfn, stack_id)
    db_cluster_parameter_groups_gone = (
        "DBParameterGroupNotFound",
        f"DBClusterParameterGroup not found: {param_group_name}",
    )
    expect_error(
        lambda: docdb.describe_db_cluster_parameter_groups(
            DBClusterParameterGroupName=param_group_name
        ),
        *db_cluster_parameter_groups_gone,
    )
    db_subnet_groups_gone = (
        "DBSubnetGroupNotFoundFault",
        f"DB Subnet group '{subnet_group_name}' not found.",
    )
    expect_error(lambda: docdb.describe_db_subnet_groups(DBSubnetGroupName=subnet_group_name),
                 *db_subnet_groups_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
