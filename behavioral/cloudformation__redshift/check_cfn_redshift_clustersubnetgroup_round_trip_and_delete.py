"""cfn-redshift-clustersubnetgroup-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-redshift-clustersubnetgroup-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "redshift"]

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


_VPC_CIDR = "10.91.0.0/16"
_SUBNET_CIDR = "10.91.1.0/24"
_DESCRIPTION = "sim2real behavioral cluster subnet group"


def _template(tag_value: str, subnet_ids=None) -> str:
    """A VPC, one subnet and a subnet group naming it (or ``subnet_ids`` instead)."""
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": _VPC_CIDR}},
            "Subnet": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {"VpcId": {"Ref": "Vpc"}, "CidrBlock": _SUBNET_CIDR,
                               "AvailabilityZone": {"Fn::Select": [0, {"Fn::GetAZs": ""}]}},
            },
            "SubnetGroup": {
                "Type": "AWS::Redshift::ClusterSubnetGroup",
                "Properties": {
                    "Description": _DESCRIPTION,
                    "SubnetIds": subnet_ids or [{"Ref": "Subnet"}],
                    "Tags": [{"Key": "sim2real-res", "Value": tag_value}],
                },
            },
        },
        "Outputs": {
            "SubnetGroupRef": {"Value": {"Ref": "SubnetGroup"}},
            "SubnetGroupName": {"Value": {"Fn::GetAtt": ["SubnetGroup", "ClusterSubnetGroupName"]}},
            "VpcId": {"Value": {"Ref": "Vpc"}},
            "SubnetId": {"Value": {"Ref": "Subnet"}},
        },
    })


def _tagged_groups(rs, tag_value: str) -> list[dict]:
    """Every cluster subnet group (all pages) carrying the template's per-run tag."""
    return paginate(rs, "describe_cluster_subnet_groups", "ClusterSubnetGroups",
                    TagKeys=["sim2real-res"], TagValues=[tag_value])


def _read_back(group: dict, out: dict) -> tuple:
    return (group["ClusterSubnetGroupName"], group["Description"], group["VpcId"],
            [s["SubnetIdentifier"] for s in group["Subnets"]])


def _want(out: dict) -> tuple:
    return (out["SubnetGroupRef"], _DESCRIPTION, out["VpcId"], [out["SubnetId"]])


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation Redshift ClusterSubnetGroup reads back through Redshift.

    Ref and GetAtt name the group Redshift lists under the run's tag, with the template's
    Description, VPC and subnet; deleting the stack removes it.
    """
    rs = ctx.client("redshift")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-cfnrs-csg-")

    stack_id = create_stack(ctx, cfn, stack, _template(stack))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"stack ended {status!r}"
    out = stack_outputs(cfn, stack_id)
    assert out["SubnetGroupName"] == out["SubnetGroupRef"], f"GetAtt vs Ref: {out!r}"

    # CloudFormation names the group, so find it by the run's template tag, not by the Ref.
    groups = _tagged_groups(rs, stack)
    got = [_read_back(g, out) for g in groups]
    assert got == [_want(out)], f"subnet groups tagged {stack!r}: {got!r}, expected {[_want(out)]!r}"
    csg_name = out["SubnetGroupRef"]

    delete_stack(cfn, stack_id)
    expect_error(lambda: rs.describe_cluster_subnet_groups(ClusterSubnetGroupName=csg_name),
                 *("ClusterSubnetGroupNotFoundFault", f"Cluster Subnet group '{csg_name}' not found."))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
