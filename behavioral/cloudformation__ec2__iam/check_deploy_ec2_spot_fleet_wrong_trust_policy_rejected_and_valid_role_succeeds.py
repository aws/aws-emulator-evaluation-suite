"""deploy-ec2-spot-fleet-wrong-trust-policy-rejected-and-valid-role-succeeds."""
from __future__ import annotations

import json
import re
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ec2-spot-fleet-wrong-trust-policy-rejected-and-valid-role-succeeds"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2", "iam"]

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


INSTANCE_TYPE = "t3.micro"
AMI_PARAMETER = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
VPC_BLOCK = "10.85.0.0/16"
SUBNET_BLOCK = "10.85.0.0/24"
_REJECTED = (
    "Parameter: SpotFleetRequestConfig.IamFleetRole is invalid. (Service: Ec2, Status Code: 400, "
    "Request ID: <id>) (SDK Attempt Count: <n>)",
    "GeneralServiceException",
)
def _spot_fleet_template(role_arn: str, tag_value: str) -> dict[str, Any]:
    t = [{"Key": "sim2real-res", "Value": tag_value}]
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "Az": {"Type": "String"},
            "Ami": {"Type": "AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>",
                     "Default": AMI_PARAMETER},
        },
        "Resources": {
            "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": VPC_BLOCK}},
            "Subnet": {"Type": "AWS::EC2::Subnet", "Properties": {
                "VpcId": {"Ref": "Vpc"}, "CidrBlock": SUBNET_BLOCK,
                "AvailabilityZone": {"Ref": "Az"}}},
            "Lt": {"Type": "AWS::EC2::LaunchTemplate", "Properties": {
                "LaunchTemplateData": {
                    "ImageId": {"Ref": "Ami"}, "InstanceType": INSTANCE_TYPE,
                    "TagSpecifications": [{"ResourceType": "instance", "Tags": t},
                                          {"ResourceType": "volume", "Tags": t}],
                },
            }},
            "Fleet": {"Type": "AWS::EC2::SpotFleet", "Properties": {
                "SpotFleetRequestConfigData": {
                    "IamFleetRole": role_arn,
                    "AllocationStrategy": "lowestPrice",
                    "TargetCapacity": 1,
                    "Type": "maintain",
                    "TerminateInstancesWithExpiration": True,
                    "LaunchTemplateConfigs": [{
                        "LaunchTemplateSpecification": {
                            "LaunchTemplateId": {"Ref": "Lt"}, "Version": "$Latest",
                        },
                        "Overrides": [{"SubnetId": {"Ref": "Subnet"}}],
                    }],
                    "TagSpecifications": [{"ResourceType": "spot-fleet-request", "Tags": t}],
                },
            }},
        },
        "Outputs": {
            "SpotFleetId": {"Value": {"Ref": "Fleet"}},
            "LtId": {"Value": {"Ref": "Lt"}},
            "SubnetId": {"Value": {"Ref": "Subnet"}},
        },
    }


def _usable_az(ec2) -> str:
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [INSTANCE_TYPE]}])["InstanceTypeOfferings"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert usable, f"no available AZ offers {INSTANCE_TYPE!r}; offerings were {sorted(offered)!r}"
    return usable[0]


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` codes mean
    the resource is already gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _create_role(iam, ctx, *, trust_service: str) -> str:
    """A fresh role naming ``trust_service`` as its only trusted principal."""
    role_name = ctx.unique_name("sim2real-xsvc-sfrole-")
    trust_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": trust_service},
            "Action": "sts:AssumeRole",
        }],
    })
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real", "Value": role_name}])["Role"]
    partition = role["Arn"].split(":")[1]
    policy_arn = f"arn:{partition}:iam::aws:policy/service-role/AmazonEC2SpotFleetTaggingRole"
    # LIFO: register delete_role first so detach_role_policy (registered second) runs first.
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    ctx.on_cleanup(_teardown(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn),
        "NoSuchEntity"))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    return role["Arn"]


def _spot_fleet_ids_with_role(ec2, role_arn: str) -> list[str]:
    return [cfg["SpotFleetRequestId"]
            for cfg in paginate(ec2, "describe_spot_fleet_requests", "SpotFleetRequestConfigs")
            if cfg["SpotFleetRequestConfig"].get("IamFleetRole") == role_arn]


def _poll(read, done, timeout_s: float, what: str):
    """``read()`` every 5 s until ``done(value)``; the last value past the deadline fails."""
    deadline = time.monotonic() + timeout_s
    while True:
        value = read()
        if done(value):
            return value
        if time.monotonic() > deadline:
            raise AssertionError(f"{what} still {value!r} after {timeout_s:.0f}s")
        time.sleep(5)


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation spot fleet whose IamFleetRole trusts the wrong service is refused.

    The control (role trusting spotfleet.amazonaws.com) deploys first as the IAM barrier, runs an
    instance and cancels; the same template trusting ec2.amazonaws.com then rolls back, no fleet.
    """
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    az = _usable_az(ec2)
    params = [{"ParameterKey": "Az", "ParameterValue": az}]
    good_role_arn = _create_role(iam, ctx, trust_service="spotfleet.amazonaws.com")
    bad_role_arn = _create_role(iam, ctx, trust_service="ec2.amazonaws.com")

    # Positive control first: a fresh role can be refused until IAM propagates, with the very
    # reason the negative grades, so only that exact reason is retried (new stack each time).
    deadline = time.monotonic() + 150
    while True:
        tag_value = ctx.unique_name("sim2real-xsvc-spotfleetok-")
        stack_id = create_stack(ctx, cfn, tag_value,
                                json.dumps(_spot_fleet_template(good_role_arn, tag_value)),
                                Parameters=params)
        status = wait_stack(cfn, stack_id)
        if status == "CREATE_COMPLETE":
            break
        reason = handler_reason(failed_reason(stack_events(cfn, stack_id), "Fleet"), ctx.account)
        delete_stack(cfn, stack_id)
        assert reason == _REJECTED and time.monotonic() < deadline, (
            f"the control stack ended {status!r} with {reason!r}"
        )
        # fixed-wait: paces retries of a whole stack re-create, not a poll of a cheap read
        time.sleep(10)
    outputs = stack_outputs(cfn, stack_id)
    fleet_id = outputs["SpotFleetId"]
    params_out = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["Parameters"]
    ami = next(p["ResolvedValue"] for p in params_out if p["ParameterKey"] == "Ami")

    # Ref against an independent read: the one fleet request naming the control role.
    assert _spot_fleet_ids_with_role(ec2, good_role_arn) == [fleet_id], "control fleet listing"
    config = _poll(
        lambda: ec2.describe_spot_fleet_requests(
            SpotFleetRequestIds=[fleet_id])["SpotFleetRequestConfigs"][0],
        lambda c: c["SpotFleetRequestState"] != "submitted", 150, "spot fleet request")
    data = config["SpotFleetRequestConfig"]
    got = (config["SpotFleetRequestState"], data["TargetCapacity"], data["IamFleetRole"],
           data["AllocationStrategy"], data["Type"], data["TerminateInstancesWithExpiration"],
           data["LaunchTemplateConfigs"])
    want = ("active", 1, good_role_arn, "lowestPrice", "maintain", True, [{
        "LaunchTemplateSpecification": {"LaunchTemplateId": outputs["LtId"], "Version": "$Latest"},
        "Overrides": [{"SubnetId": outputs["SubnetId"]}],
    }])
    assert got == want, f"EC2 reports spot fleet {got!r}, expected {want!r}"

    instances = _poll(
        lambda: ec2.describe_spot_fleet_instances(SpotFleetRequestId=fleet_id)["ActiveInstances"],
        bool, 150, "spot fleet instances")
    assert len(instances) == 1, f"EC2 reports {instances!r} active spot fleet instances"
    instance_id = instances[0]["InstanceId"]
    ec2.get_waiter("instance_running").wait(
        InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    inst = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
    got = (inst["InstanceType"], inst["SubnetId"], inst["ImageId"],
           {"Key": "sim2real-res", "Value": tag_value} in inst.get("Tags", []))
    assert got == (INSTANCE_TYPE, outputs["SubnetId"], ami, True), f"fleet instance reads {got!r}"

    # Deleting the control cancels the request and terminates its instance (terminal states).
    delete_stack(cfn, stack_id)
    ec2.get_waiter("instance_terminated").wait(
        InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    # cancelled_terminating can outlast the instance's own termination by minutes.
    state = _poll(
        lambda: ec2.describe_spot_fleet_requests(
            SpotFleetRequestIds=[fleet_id])["SpotFleetRequestConfigs"][0]["SpotFleetRequestState"],
        lambda st: st == "cancelled", 420, "spot fleet request state")
    assert state == "cancelled", f"spot fleet request ended {state!r}"

    # The negative: the same template naming the role spotfleet.amazonaws.com cannot assume.
    bad_tag = ctx.unique_name("sim2real-xsvc-spotfleetbad-")
    bad_id = create_stack(ctx, cfn, bad_tag, json.dumps(_spot_fleet_template(bad_role_arn, bad_tag)),
                          Parameters=params)
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"a spot fleet with an unassumable role ended {status!r}"
    events = stack_events(cfn, bad_id)
    failed = [r for r in decisive_rows(events) if r[1] == "CREATE_FAILED"]
    assert failed == [("Fleet", "CREATE_FAILED")], f"CREATE_FAILED rows {failed!r}"
    got = handler_reason(failed_reason(events, "Fleet"), ctx.account)
    assert got == _REJECTED, f"CREATE_FAILED reason {got!r}, expected {_REJECTED!r}"
    leaked = _spot_fleet_ids_with_role(ec2, bad_role_arn)
    assert leaked == [], f"a spot fleet request referencing the rejected role exists: {leaked!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
