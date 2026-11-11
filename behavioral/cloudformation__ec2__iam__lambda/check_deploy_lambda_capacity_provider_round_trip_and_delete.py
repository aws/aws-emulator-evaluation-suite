"""deploy-lambda-capacity-provider-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-lambda-capacity-provider-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2", "iam", "lambda"]

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


# ---- Check-specific: the template, then run(). ----

_VPC_CIDR = "10.98.0.0/16"
_SUBNET_CIDR = "10.98.1.0/24"
_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
}
#: The EC2 actions Lambda Managed Instances needs from the capacity provider's operator role.
_OPERATOR_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": [
            "ec2:RunInstances", "ec2:TerminateInstances", "ec2:DescribeInstances",
            "ec2:DescribeInstanceTypes", "ec2:DescribeInstanceTypeOfferings",
            "ec2:DescribeImages", "ec2:DescribeSubnets",
            "ec2:DescribeSecurityGroups", "ec2:DescribeVpcs", "ec2:CreateTags",
            "ec2:DescribeTags", "ec2:CreateLaunchTemplate", "ec2:DescribeLaunchTemplates",
            "ec2:DeleteLaunchTemplate", "ec2:CreateFleet", "ec2:DescribeFleets",
            "ec2:DeleteFleets", "ec2:CreateNetworkInterface", "ec2:DeleteNetworkInterface",
            "ec2:DescribeNetworkInterfaces", "ec2:AttachNetworkInterface",
            "ec2:DetachNetworkInterface",
        ],
        "Resource": "*",
    }],
}


def _template(provider_name, role_name, az, architecture):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": _VPC_CIDR}},
            "Subnet": {"Type": "AWS::EC2::Subnet", "Properties": {
                "VpcId": {"Ref": "Vpc"}, "CidrBlock": _SUBNET_CIDR, "AvailabilityZone": az,
            }},
            "Sg": {"Type": "AWS::EC2::SecurityGroup", "Properties": {
                "GroupDescription": "sim2real capacity provider sg", "VpcId": {"Ref": "Vpc"},
            }},
            "OperatorRole": {"Type": "AWS::IAM::Role", "Properties": {
                "RoleName": role_name,
                "AssumeRolePolicyDocument": _TRUST,
                "Policies": [{"PolicyName": "operator", "PolicyDocument": _OPERATOR_POLICY}],
            }},
            "Provider": {"Type": "AWS::Lambda::CapacityProvider", "Properties": {
                "CapacityProviderName": provider_name,
                "VpcConfig": {"SubnetIds": [{"Ref": "Subnet"}],
                              "SecurityGroupIds": [{"Ref": "Sg"}]},
                "PermissionsConfig": {
                    "CapacityProviderOperatorRoleArn": {"Fn::GetAtt": ["OperatorRole", "Arn"]}},
                "InstanceRequirements": {"Architectures": [architecture]},
                "Tags": [{"Key": "sim2real-lcp", "Value": provider_name}],
            }},
        },
        "Outputs": {
            "ProviderName": {"Value": {"Ref": "Provider"}},
            "ProviderArn": {"Value": {"Fn::GetAtt": ["Provider", "Arn"]}},
            "ProviderState": {"Value": {"Fn::GetAtt": ["Provider", "State"]}},
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


def _check_provider(awslambda, iam, name, role_name, out, stack, architecture):
    """The provider by its templated name, every templated property and tag, and its role."""
    listed = [p["CapacityProviderArn"] for p in paginate(
        awslambda, "list_capacity_providers", "CapacityProviders")
        if p["CapacityProviderArn"].rsplit(":", 1)[1] == name]
    assert listed == [out["ProviderArn"]], f"ListCapacityProviders for {name!r}: {listed!r}"
    got = awslambda.get_capacity_provider(CapacityProviderName=name)["CapacityProvider"]
    fields = (got["CapacityProviderArn"], got["State"], got["VpcConfig"]["SubnetIds"],
              got["VpcConfig"]["SecurityGroupIds"],
              got["PermissionsConfig"]["CapacityProviderOperatorRoleArn"],
              got["InstanceRequirements"]["Architectures"])
    want = (out["ProviderArn"], "Active", [out["SubnetId"]], [out["SgId"]], out["RoleArn"],
            [architecture])
    assert fields == want, f"GetCapacityProvider reads {fields!r}, expected {want!r}"
    tags_ = {k: v for k, v in awslambda.list_tags(Resource=out["ProviderArn"])["Tags"].items()
             if not k.startswith("aws:")}
    assert tags_ == {"sim2real": stack, "sim2real-lcp": name}, f"provider tags {tags_!r}"
    role = iam.get_role(RoleName=role_name)["Role"]
    assert (role["Arn"], role["AssumeRolePolicyDocument"]) == (out["RoleArn"], _TRUST), (
        f"operator role {role!r}"
    )
    doc = iam.get_role_policy(RoleName=role_name, PolicyName="operator")["PolicyDocument"]
    assert doc == _OPERATOR_POLICY, f"operator inline policy {doc!r}"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation Lambda CapacityProvider reads back Active through Lambda with its VPC
    config, operator role, architecture and tags, the role through IAM; deleting the stack
    removes the provider.
    """
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    awslambda = ctx.client("lambda")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-lcp-")
    provider_name = ctx.unique_name("sim2real-lcp-prov-")
    role_name = ctx.unique_name("sim2real-lcp-role-")
    az = _usable_az(ec2)

    stack_id = create_stack(ctx, cfn, stack, _template(provider_name, role_name, az, "x86_64"),
                            Capabilities=["CAPABILITY_NAMED_IAM"])
    status = wait_stack(cfn, stack_id, timeout_s=900.0)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    assert (out["ProviderName"], out["ProviderState"]) == (provider_name, "Active"), (
        f"Ref / GetAtt State {(out['ProviderName'], out['ProviderState'])!r}"
    )
    _check_provider(awslambda, iam, provider_name, role_name, out, stack, "x86_64")

    delete_stack(cfn, stack_id)
    listed = [p["CapacityProviderArn"] for p in paginate(
        awslambda, "list_capacity_providers", "CapacityProviders")
        if p["CapacityProviderArn"] == out["ProviderArn"]]
    assert listed == [], f"the deleted provider is still listed: {listed!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
