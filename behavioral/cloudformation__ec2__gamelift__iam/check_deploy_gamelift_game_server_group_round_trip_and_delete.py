"""deploy-gamelift-game-server-group-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-gamelift-game-server-group-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2", "gamelift", "iam"]

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

_DEADLINE_S = 900.0
_VPC_CIDR = "10.123.0.0/16"
_SUBNET_CIDR = "10.123.1.0/24"
_WANT_TYPES = ["c5.large", "c4.large"]
_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow",
                   "Principal": {"Service": ["gamelift.amazonaws.com", "autoscaling.amazonaws.com"]},
                   "Action": "sts:AssumeRole"}],
}


def _template(role_name, group_name, az, instance_types):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"Ami": {"Type": "AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>",
                               "Default": _AMI_PARAM}},
        "Resources": {
            "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": _VPC_CIDR}},
            "Subnet": {"Type": "AWS::EC2::Subnet", "Properties": {
                "VpcId": {"Ref": "Vpc"}, "CidrBlock": _SUBNET_CIDR, "AvailabilityZone": az,
            }},
            "LaunchTemplate": {"Type": "AWS::EC2::LaunchTemplate", "Properties": {
                "LaunchTemplateData": {"InstanceType": "c5.large", "ImageId": {"Ref": "Ami"}},
            }},
            "GsgRole": {"Type": "AWS::IAM::Role", "Properties": {
                "RoleName": role_name,
                "AssumeRolePolicyDocument": _TRUST,
                "ManagedPolicyArns": [{"Fn::Sub": "arn:${AWS::Partition}:iam::aws:policy/"
                                                  "GameLiftGameServerGroupPolicy"}],
            }},
            "Group": {"Type": "AWS::GameLift::GameServerGroup", "Properties": {
                "GameServerGroupName": group_name,
                "RoleArn": {"Fn::GetAtt": ["GsgRole", "Arn"]},
                "MinSize": 0,
                "MaxSize": 1,
                "LaunchTemplate": {"LaunchTemplateId": {"Ref": "LaunchTemplate"}},
                "InstanceDefinitions": [{"InstanceType": x} for x in instance_types],
                "VpcSubnets": [{"Ref": "Subnet"}],
                "DeleteOption": "FORCE_DELETE",
                "Tags": [{"Key": "sim2real-gsg", "Value": group_name}],
            }},
        },
        "Outputs": {
            "GroupArnOut": {"Value": {"Ref": "Group"}},
            "AsgArnOut": {"Value": {"Fn::GetAtt": ["Group", "AutoScalingGroupArn"]}},
            "RoleArnOut": {"Value": {"Fn::GetAtt": ["GsgRole", "Arn"]}},
        },
    })


def _usable_az(ec2, instance_types):
    offered_sets = []
    for t in instance_types:
        offs = ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [t]}])["InstanceTypeOfferings"]
        offered_sets.append({o["Location"] for o in offs})
    common = set.intersection(*offered_sets)
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in common)
    assert usable, f"no available AZ offers every instance type in {instance_types!r}"
    return usable[0]


def _group_arns(gl, name):
    return [g["GameServerGroupArn"] for g in
            paginate(gl, "list_game_server_groups", "GameServerGroups")
            if g["GameServerGroupName"] == name]


def _check_group(gl, iam, name, role_name, out, stack, instance_types):
    """The group by its templated name with role, instance types and tags; the role via IAM."""
    assert _group_arns(gl, name) == [out["GroupArnOut"]], f"ListGameServerGroups for {name!r}"
    got = gl.describe_game_server_group(GameServerGroupName=name)["GameServerGroup"]
    fields = (got["GameServerGroupArn"], got["AutoScalingGroupArn"], got["RoleArn"],
              [d["InstanceType"] for d in got["InstanceDefinitions"]], got["Status"])
    want = (out["GroupArnOut"], out["AsgArnOut"], out["RoleArnOut"], instance_types, "ACTIVE")
    assert fields == want, f"DescribeGameServerGroup reads {fields!r}, expected {want!r}"
    tags_ = {t["Key"]: t["Value"] for t in
             gl.list_tags_for_resource(ResourceARN=out["GroupArnOut"])["Tags"]
             if not t["Key"].startswith("aws:")}
    assert tags_ == {"sim2real": stack, "sim2real-gsg": name}, f"group tags {tags_!r}"
    role = iam.get_role(RoleName=role_name)["Role"]
    assert (role["Arn"], _service_sets(role["AssumeRolePolicyDocument"])) == (
        out["RoleArnOut"], _service_sets(_TRUST)), (
        f"role {role!r}"
    )
    attached = [p["PolicyName"] for p in paginate(iam, "list_attached_role_policies",
                                                  "AttachedPolicies", RoleName=role_name)]
    assert attached == ["GameLiftGameServerGroupPolicy"], f"attached policies {attached!r}"


def _service_sets(doc):
    """The trust policy with each Principal Service list as a set: IAM returns it in any order."""
    return {**doc, "Statement": [
        {**st, "Principal": {**st["Principal"], "Service": set(st["Principal"]["Service"])}}
        for st in doc["Statement"]]}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation GameLift GameServerGroup (sized 0..1, so it launches nothing) reads back
    ACTIVE through GameLift with its role, instance types and tags, the role through IAM;
    deleting the stack removes the group.
    """
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    gl = ctx.client("gamelift")
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cfgsg-role-")
    group_name = ctx.unique_name("sim2real-cfgsg-")
    stack = ctx.unique_name("sim2real-cfgsg-")
    az = _usable_az(ec2, _WANT_TYPES)

    stack_id = create_stack(ctx, cfn, stack, _template(role_name, group_name, az, _WANT_TYPES),
                            Capabilities=["CAPABILITY_NAMED_IAM"])
    status = wait_stack(cfn, stack_id, timeout_s=_DEADLINE_S)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    partition = stack_id.split(":")[1]
    arn = f"arn:{partition}:gamelift:{ctx.region}:{ctx.account}:gameservergroup/{group_name}"
    assert out["GroupArnOut"] == arn, f"Ref {out['GroupArnOut']!r}, expected {arn!r}"
    _check_group(gl, iam, group_name, role_name, out, stack, _WANT_TYPES)

    delete_stack(cfn, stack_id)
    refused = ("NotFoundException", f"Game server group {arn} does not exists on account")
    expect_error(lambda: gl.describe_game_server_group(GameServerGroupName=group_name), *refused)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
