"""deploy-ec2-egress-only-internet-gateway-and-vpc-encryption-control-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ec2-egress-only-internet-gateway-and-vpc-encryption-control-round-trip-and-delete"
GROUP = "deploy-ec2-resource-sweep"
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

_VPC_CIDR = "10.95.0.0/16"


def _template(tag_value: str) -> str:
    t = [{"Key": "sim2real-check", "Value": tag_value}]
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": _VPC_CIDR, "Tags": t}},
            "Eigw": {
                "Type": "AWS::EC2::EgressOnlyInternetGateway",
                "Properties": {"VpcId": {"Ref": "Vpc"}},
            },
            "EncryptionControl": {
                "Type": "AWS::EC2::VPCEncryptionControl",
                "Properties": {"VpcId": {"Ref": "Vpc"}, "Mode": "monitor"},
            },
        },
        "Outputs": {
            "VpcId": {"Value": {"Ref": "Vpc"}},
            "EigwId": {"Value": {"Ref": "Eigw"}},
            "EncryptionControlId": {"Value": {"Ref": "EncryptionControl"}},
            "EigwGetAttId": {"Value": {"Fn::GetAtt": ["Eigw", "Id"]}},
            "EncryptionControlGetAttId": {
                "Value": {"Fn::GetAtt": ["EncryptionControl", "VpcEncryptionControlId"]},
            },
        },
    })


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::EC2::EgressOnlyInternetGateway attaches to its VPC and an
    AWS::EC2::VPCEncryptionControl reaches Mode 'monitor' in EC2's own views; deleting the stack
    removes the gateway and the VPC, and the encryption control follows the VPC.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-egressonlyinternetgateway.html
    """
    ec2 = ctx.client("ec2")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-ec2eigw-")

    stack_id = create_stack(ctx, cfn, stack, _template(CHECK))

    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"stack {stack!r} ended {status!r}, expected CREATE_COMPLETE"

    outputs = stack_outputs(cfn, stack_id)
    vpc_id, eigw_id = outputs["VpcId"], outputs["EigwId"]
    control_id = outputs["EncryptionControlId"]

    gws = ec2.describe_egress_only_internet_gateways(
        EgressOnlyInternetGatewayIds=[eigw_id])["EgressOnlyInternetGateways"]
    assert gws, f"DescribeEgressOnlyInternetGateways({eigw_id!r}) returned nothing"
    got_ids = (outputs["EigwGetAttId"], eigw_id)
    want_ids = (gws[0]["EgressOnlyInternetGatewayId"],) * 2
    assert got_ids == want_ids, (
        f"(GetAtt Eigw.Id, Ref Eigw) {got_ids!r}, EC2 reports the gateway id {want_ids[0]!r}"
    )
    attachments = gws[0]["Attachments"]
    assert attachments == [{"VpcId": vpc_id, "State": "attached"}], (
        f"expected exactly one 'attached' attachment to {vpc_id!r}, EC2 reports {attachments!r}"
    )

    controls = ec2.describe_vpc_encryption_controls(
        VpcEncryptionControlIds=[control_id])["VpcEncryptionControls"]
    assert controls, f"DescribeVpcEncryptionControls({control_id!r}) returned nothing"
    control = controls[0]
    got_ids = (outputs["EncryptionControlGetAttId"], control_id)
    want_ids = (control["VpcEncryptionControlId"],) * 2
    assert got_ids == want_ids, (
        f"(GetAtt VpcEncryptionControlId, Ref) {got_ids!r}, EC2 reports {want_ids[0]!r}"
    )
    assert control["VpcId"] == vpc_id, (
        f"expected the encryption control's VpcId to be {vpc_id!r}, EC2 reports "
        f"{control['VpcId']!r}"
    )
    assert control["Mode"] == "monitor", (
        f"expected the encryption control's Mode to be 'monitor', EC2 reports {control['Mode']!r}"
    )

    delete_stack(cfn, stack_id)
    stack_gone = ("ValidationError", f"Stack with id {stack} does not exist")
    expect_error(lambda: cfn.describe_stacks(StackName=stack), *stack_gone)

    # DescribeEgressOnlyInternetGateways by explicit id answers a deleted gateway with an empty
    # result set rather than a NotFound error.
    after_gws = ec2.describe_egress_only_internet_gateways(
        EgressOnlyInternetGatewayIds=[eigw_id])["EgressOnlyInternetGateways"]
    assert after_gws == [], (
        f"expected no egress-only gateway for the deleted id {eigw_id!r}, EC2 reports "
        f"{after_gws!r}"
    )

    vpcs_gone = ("InvalidVpcID.NotFound", f"The vpc ID '{vpc_id}' does not exist")
    expect_error(lambda: ec2.describe_vpcs(VpcIds=[vpc_id]), *vpcs_gone)

    vpc_encryption_controls_gone = (
        "InvalidVpcEncryptionControlId.NotFound",
        "One or more of the VpcEncryptionControlIds provided do not exist",
    )
    expect_error(
        lambda: ec2.describe_vpc_encryption_controls(VpcEncryptionControlIds=[control_id]),
        *vpc_encryption_controls_gone,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
