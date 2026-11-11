"""deploy-gamelift-game-server-group-invalid-instance-type-rejected-and-rolled-back."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-gamelift-game-server-group-invalid-instance-type-rejected-and-rolled-back"
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
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


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


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


def masked(text, account, *names):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count, account, run names."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


def handler_reason(reason, account, *names):
    """``(masked message, HandlerErrorCode)`` of a registry-handler reason; compare with ==."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return masked(m["message"], account, *names), m["code"]


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
_VPC_CIDR = "10.126.0.0/16"
_SUBNET_CIDR = "10.126.1.0/24"
_BAD_TYPE = "t3.micro"
_GOOD_TYPES = ["c5.large", "c4.large"]
_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
# Quoted verbatim from AWS's own enum-violation error text for an exact-message assertion;
# none of these is ever launched. large-instance: quoted-only, not launched.
_VALID_TYPES_CSV = (
    "g4dn.4xlarge, m5a.2xlarge, r6g.medium, c5.12xlarge, c5.9xlarge, c4.xlarge, g4ad.xlarge, "  # large-instance: quoted-only, not launched
    "c6g.8xlarge, c6g.large, c5.24xlarge, m5a.4xlarge, c6g.16xlarge, c5a.xlarge, g5.xlarge, "  # large-instance: quoted-only, not launched
    "c5a.12xlarge, g5.12xlarge, g4dn.8xlarge, c5a.24xlarge, g5.24xlarge, m6g.2xlarge, "  # large-instance: quoted-only, not launched
    "m6g.medium, r5a.2xlarge, g4ad.16xlarge, m5a.8xlarge, m5a.large, c5.18xlarge, g5.48xlarge, "  # large-instance: quoted-only, not launched
    "m6g.4xlarge, r5a.4xlarge, c5a.16xlarge, g5.16xlarge, m5.xlarge, m4.10xlarge, r4.2xlarge, "  # large-instance: quoted-only, not launched
    "m5.12xlarge, m4.xlarge, r6g.2xlarge, r5.2xlarge, m6g.8xlarge, m6g.large, m5.24xlarge, "  # large-instance: quoted-only, not launched
    "r5a.8xlarge, r5a.large, r4.4xlarge, r6g.4xlarge, r5.4xlarge, m5.16xlarge, m4.2xlarge, "  # large-instance: quoted-only, not launched
    "r6g.xlarge, r5.xlarge, m5.2xlarge, r6g.12xlarge, r5.12xlarge, r4.8xlarge, r4.xlarge, "  # large-instance: quoted-only, not launched
    "r4.large, c6g.medium, m4.4xlarge, r6g.8xlarge, r6g.large, r5.24xlarge, r5.8xlarge, "  # large-instance: quoted-only, not launched
    "r5.large, m5.4xlarge, m6g.xlarge, r6g.16xlarge, r5a.xlarge, r5.16xlarge, m6g.12xlarge, "  # large-instance: quoted-only, not launched
    "m4.large, r5a.12xlarge, r4.16xlarge, g5.2xlarge, m5.8xlarge, m5.large, r5a.24xlarge, "  # large-instance: quoted-only, not launched
    "c5a.2xlarge, g5.4xlarge, g4ad.2xlarge, m6g.16xlarge, m5a.xlarge, r5a.16xlarge, "  # large-instance: quoted-only, not launched
    "c5a.4xlarge, c4.2xlarge, g4ad.4xlarge, m5a.12xlarge, c5.2xlarge, g4dn.xlarge, "  # large-instance: quoted-only, not launched
    "m5a.24xlarge, c4.4xlarge, g5.8xlarge, g4dn.12xlarge, c6g.2xlarge, c5.4xlarge, "  # large-instance: quoted-only, not launched
    "c5a.8xlarge, c5a.large, g4ad.8xlarge, m5a.16xlarge, c6g.4xlarge, c6g.xlarge, "  # large-instance: quoted-only, not launched
    "g4dn.2xlarge, c6g.12xlarge, c4.8xlarge, c4.large, g4dn.16xlarge, c5.xlarge, c5.large"  # large-instance: quoted-only, not launched
)
_REJECTED = (
    "1 validation error detected: Value at 'instanceDefinitions.1.member.instanceType' "
    f"failed to satisfy constraint: Member must satisfy enum value set: [{_VALID_TYPES_CSV}] "
    "(Service: GameLift, Status Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)",
    "InvalidRequest",
)
_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow",
                   "Principal": {"Service": ["gamelift.amazonaws.com", "autoscaling.amazonaws.com"]},
                   "Action": "sts:AssumeRole"}],
}


def _service_sets(doc):
    """The trust policy with each Principal Service list as a set: IAM returns it in any order."""
    return {**doc, "Statement": [
        {**st, "Principal": {**st["Principal"], "Service": set(st["Principal"]["Service"])}}
        for st in doc["Statement"]]}


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
    got = (role["Arn"], _service_sets(role["AssumeRolePolicyDocument"]))
    assert got == (out["RoleArnOut"], _service_sets(_TRUST)), (
        f"role {role!r}"
    )
    attached = [p["PolicyName"] for p in paginate(iam, "list_attached_role_policies",
                                                  "AttachedPolicies", RoleName=role_name)]
    assert attached == ["GameLiftGameServerGroupPolicy"], f"attached policies {attached!r}"


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation GameLift GameServerGroup naming an instance type outside GameLift's
    supported set is refused with the exact enum violation and rolls back with no group left,
    while the same template with a supported type deploys and reads back.
    """
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    gl = ctx.client("gamelift")
    iam = ctx.client("iam")
    az = _usable_az(ec2, _GOOD_TYPES)
    bad_group = ctx.unique_name("sim2real-cfgsgbad-")

    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-cfgsgbad-"),
                          _template(ctx.unique_name("sim2real-cfgsgbad-role-"), bad_group, az,
                                    [_BAD_TYPE, _GOOD_TYPES[1]]),
                          Capabilities=["CAPABILITY_NAMED_IAM"])
    status = wait_stack(cfn, bad_id, timeout_s=_DEADLINE_S)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    got = handler_reason(failed_reason(stack_events(cfn, bad_id), "Group"), ctx.account)
    assert got == _REJECTED, f"Group reason {got!r}, expected {_REJECTED!r}"
    # Rollback absence through GameLift, by the name the group would have, before the delete.
    assert _group_arns(gl, bad_group) == [], f"the rejected group {bad_group!r} is listed"
    bad_arn = (f"arn:{bad_id.split(':')[1]}:gamelift:{ctx.region}:{ctx.account}:"
               f"gameservergroup/{bad_group}")
    refused = ("NotFoundException", f"Game server group {bad_arn} does not exists on account")
    expect_error(lambda: gl.describe_game_server_group(GameServerGroupName=bad_group), *refused)

    # Positive control: the same template with the first instance type supported.
    good_stack = ctx.unique_name("sim2real-cfgsggood-")
    good_group = ctx.unique_name("sim2real-cfgsggood-")
    good_role = ctx.unique_name("sim2real-cfgsggood-role-")
    good_id = create_stack(ctx, cfn, good_stack, _template(good_role, good_group, az, _GOOD_TYPES),
                           Capabilities=["CAPABILITY_NAMED_IAM"])
    status = wait_stack(cfn, good_id, timeout_s=_DEADLINE_S)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}: {decisive_rows(stack_events(cfn, good_id))!r}"
    )
    _check_group(gl, iam, good_group, good_role, stack_outputs(cfn, good_id), good_stack,
                 _GOOD_TYPES)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
