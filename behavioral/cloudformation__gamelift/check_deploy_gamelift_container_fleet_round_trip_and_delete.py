"""deploy-gamelift-container-fleet-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-gamelift-container-fleet-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "gamelift"]

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

_INSTANCE_TYPE = "c5.large"
_BILLING_TYPE = "SPOT"


def _template(role_name, fleet_role_arn=None):
    """``fleet_role_arn`` overrides the fleet's FleetRoleArn (default: the stack's own role)."""
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "FleetRole": {"Type": "AWS::IAM::Role", "Properties": {
                "RoleName": role_name,
                "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [{
                    "Effect": "Allow", "Principal": {"Service": "gamelift.amazonaws.com"},
                    "Action": "sts:AssumeRole"}]},
                "ManagedPolicyArns": [{"Fn::Sub": "arn:${AWS::Partition}:iam::aws:policy/"
                                                  "GameLiftContainerFleetPolicy"}],
            }},
            "Fleet": {"Type": "AWS::GameLift::ContainerFleet", "Properties": {
                "FleetRoleArn": fleet_role_arn or {"Fn::GetAtt": ["FleetRole", "Arn"]},
                "InstanceType": _INSTANCE_TYPE,
                "BillingType": _BILLING_TYPE,
                "Tags": [{"Key": "sim2real-gl", "Value": role_name}],
            }},
        },
        "Outputs": {
            "FleetIdOut": {"Value": {"Ref": "Fleet"}},
            "FleetArnOut": {"Value": {"Fn::GetAtt": ["Fleet", "FleetArn"]}},
            "FleetRoleArnOut": {"Value": {"Fn::GetAtt": ["FleetRole", "Arn"]}},
        },
    })


def _fleets_with_role(gl, role_arn):
    return [f["FleetId"] for f in paginate(gl, "list_container_fleets", "ContainerFleets")
            if f.get("FleetRoleArn") == role_arn]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation GameLift container fleet reads back with its role, instance and billing type.

    Ref and GetAtt match an independent listing, and deleting the stack removes the fleet.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-gamelift-containerfleet.html
    """
    cf = ctx.client("cloudformation")
    gl = ctx.client("gamelift")
    stack = ctx.unique_name("sim2real-cfcf-")
    role_name = ctx.unique_name("sim2real-cfcf-role-")

    stack_id = create_stack(ctx, cf, stack, _template(role_name),
                            Capabilities=["CAPABILITY_NAMED_IAM"])
    status = wait_stack(cf, stack_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    out = stack_outputs(cf, stack_id)
    partition = stack_id.split(":")[1]
    role_arn = f"arn:{partition}:iam::{ctx.account}:role/{role_name}"

    # Ref against an independent ListContainerFleets, found by the stack's own role.
    assert out["FleetRoleArnOut"] == role_arn, f"role GetAtt {out['FleetRoleArnOut']!r}"
    assert _fleets_with_role(gl, role_arn) == [out["FleetIdOut"]], (
        f"ListContainerFleets {_fleets_with_role(gl, role_arn)!r}, Ref {out['FleetIdOut']!r}"
    )
    fleet = gl.describe_container_fleet(FleetId=out["FleetIdOut"])["ContainerFleet"]
    got = (fleet["FleetArn"], fleet["FleetRoleArn"], fleet["InstanceType"], fleet["BillingType"],
           fleet["Status"])
    assert got == (out["FleetArnOut"], role_arn, _INSTANCE_TYPE, _BILLING_TYPE, "CREATED"), (
        f"DescribeContainerFleet {got!r}"
    )
    fleet_tags = {t["Key"]: t["Value"] for t in gl.list_tags_for_resource(
        ResourceARN=fleet["FleetArn"])["Tags"] if not t["Key"].startswith("aws:")}
    assert fleet_tags == {"sim2real": stack, "sim2real-gl": role_name}, f"tags {fleet_tags!r}"

    delete_stack(cf, stack_id)
    not_found = ("NotFoundException", f"Fleet {out['FleetIdOut']} does not exist")
    expect_error(lambda: gl.describe_container_fleet(FleetId=out["FleetIdOut"]), *not_found)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
