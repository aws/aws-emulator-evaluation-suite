"""deploy-lambda-network-connector-invalid-protocol-rejected-and-rolled-back."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-lambda-network-connector-invalid-protocol-rejected-and-rolled-back"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2", "lambda-core"]

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


def validation_rows(cf, stack_id):
    """Sorted ``(logical id, ValidationName, Status, FailureMode, Reason, Path)`` rows."""
    return sorted(
        (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
         e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
        for e in paginate(cf, "describe_events", "OperationEvents", StackName=stack_id)
        if e.get("EventType") == "VALIDATION_ERROR"
    )


# ---- Check-specific: the template, then run(). ----

_VPC_CIDR = "10.96.0.0/16"
_SUBNET_CIDR = "10.96.1.0/24"
_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
}
#: The ENI actions the network connector's operator role needs in the check's own VPC.
_OPERATOR_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": [
            "ec2:CreateNetworkInterface", "ec2:DeleteNetworkInterface",
            "ec2:DescribeNetworkInterfaces", "ec2:AttachNetworkInterface",
            "ec2:DetachNetworkInterface", "ec2:DescribeSubnets",
            "ec2:DescribeSecurityGroups", "ec2:DescribeVpcs",
            "ec2:AssignPrivateIpAddresses", "ec2:UnassignPrivateIpAddresses",
        ],
        "Resource": "*",
    }],
}


def _template(connector_name, role_name, az, protocol):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": _VPC_CIDR}},
            "Subnet": {"Type": "AWS::EC2::Subnet", "Properties": {
                "VpcId": {"Ref": "Vpc"}, "CidrBlock": _SUBNET_CIDR, "AvailabilityZone": az,
            }},
            "Sg": {"Type": "AWS::EC2::SecurityGroup", "Properties": {
                "GroupDescription": "sim2real network connector sg", "VpcId": {"Ref": "Vpc"},
            }},
            "OperatorRole": {"Type": "AWS::IAM::Role", "Properties": {
                "RoleName": role_name,
                "AssumeRolePolicyDocument": _TRUST,
                "Policies": [{"PolicyName": "operator", "PolicyDocument": _OPERATOR_POLICY}],
            }},
            "Connector": {"Type": "AWS::Lambda::NetworkConnector", "Properties": {
                "Name": connector_name,
                "Configuration": {"VpcEgressConfiguration": {
                    "SubnetIds": [{"Ref": "Subnet"}],
                    "SecurityGroupIds": [{"Ref": "Sg"}],
                    "NetworkProtocol": protocol,
                    "AssociatedComputeResourceTypes": ["MicroVm"],
                }},
                "OperatorRole": {"Fn::GetAtt": ["OperatorRole", "Arn"]},
            }},
        },
        "Outputs": {
            "ConnectorArn": {"Value": {"Ref": "Connector"}},
            "ConnectorState": {"Value": {"Fn::GetAtt": ["Connector", "State"]}},
            "RoleArn": {"Value": {"Fn::GetAtt": ["OperatorRole", "Arn"]}},
            "SubnetId": {"Value": {"Ref": "Subnet"}},
            "SgId": {"Value": {"Ref": "Sg"}},
        },
    })


def _usable_az(ec2):
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"])
    assert usable, "no available Availability Zone in this region"
    return usable[0]


def _listed(core, name):
    """``(Arn, Id, State)`` of every listed connector named ``name``, across all pages."""
    return [(c["Arn"], c["Id"], c["State"])
            for c in paginate(core, "list_network_connectors", "NetworkConnectors")
            if c["Name"] == name]


def _check_connector(core, name, out, protocol):
    """The connector by its templated name: listed once with the Ref, every templated property."""
    listed = _listed(core, name)
    assert [a for a, _, _ in listed] == [out["ConnectorArn"]], f"ListNetworkConnectors {listed!r}"
    got = core.get_network_connector(Identifier=name)
    egress = got["Configuration"]["VpcEgressConfiguration"]
    fields = (got["Arn"], got["Name"], got["Id"], got["State"], got["OperatorRole"],
              egress["SubnetIds"], egress["SecurityGroupIds"], egress["NetworkProtocol"],
              egress["AssociatedComputeResourceTypes"])
    want = (out["ConnectorArn"], name, listed[0][1], "ACTIVE", out["RoleArn"], [out["SubnetId"]],
            [out["SgId"]], protocol, ["MicroVm"])
    assert fields == want, f"GetNetworkConnector reads {fields!r}, expected {want!r}"


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation Lambda NetworkConnector whose NetworkProtocol is outside the enum is
    refused by early validation and creates no connector, while the same template with IPv4
    deploys and reads back through lambda-core.
    """
    ec2 = ctx.client("ec2")
    core = ctx.client("lambda-core")
    cfn = ctx.client("cloudformation")
    az = _usable_az(ec2)
    bad_connector = ctx.unique_name("sim2real-lncbad-conn-")

    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-lncbad-"),
                          _template(bad_connector, ctx.unique_name("sim2real-lncbad-role-"), az,
                                    "IPv6"),
                          Capabilities=["CAPABILITY_NAMED_IAM"])
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    rows = [r for r in validation_rows(cfn, bad_id) if r[3] == "FAIL"]
    want = [("Connector", "PROPERTY_VALIDATION", "FAILED", "FAIL",
             "IPv6 is not a valid enum value. Supported values: [IPv4, DualStack]",
             "/Resources/Connector/Properties/Configuration/VpcEgressConfiguration/"
             "NetworkProtocol")]
    assert rows == want, f"validation rows {rows!r}, expected {want!r}"
    # Absence through lambda-core, by the name the connector would have, before the delete.
    assert _listed(core, bad_connector) == [], f"{bad_connector!r} is listed"

    # Positive control: the same template with a valid NetworkProtocol.
    good_connector = ctx.unique_name("sim2real-lncgood-conn-")
    good_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-lncgood-"),
                           _template(good_connector, ctx.unique_name("sim2real-lncgood-role-"), az,
                                     "IPv4"),
                           Capabilities=["CAPABILITY_NAMED_IAM"])
    status = wait_stack(cfn, good_id, timeout_s=900.0)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}: {decisive_rows(stack_events(cfn, good_id))!r}"
    )
    _check_connector(core, good_connector, stack_outputs(cfn, good_id), "IPv4")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
