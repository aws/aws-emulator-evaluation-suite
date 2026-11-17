"""cfn-ecs-capacity-provider-managed-scaling-update-in-place-then-replaced-then-inactive."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-ecs-capacity-provider-managed-scaling-update-in-place-then-replaced-then-inactive"
GROUP = "deploy"
SERVICES = ["cloudformation", "ecs"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
#: ECS converging a capacity provider's own state after an update or a delete.
_CONVERGE_CAP_S = 180.0
_POLL_S = 3.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]

_AMI_PARAM = "/aws/service/ecs/optimized-ami/amazon-linux-2/recommended/image_id"

#: (status, targetCapacity, minimumScalingStepSize, maximumScalingStepSize, instanceWarmupPeriod)
_SCALING_OFF = ("DISABLED", 100, 1, 10000, 300)
_SCALING_ON = ("ENABLED", 75, 2, 5, 120)


def _template(cp_name: str, asg_logical: str, scaling: tuple) -> str:
    status, target, min_step, max_step, warmup = scaling
    managed_scaling = {
        "Status": status,
        "TargetCapacity": target,
        "MinimumScalingStepSize": min_step,
        "MaximumScalingStepSize": max_step,
        "InstanceWarmupPeriod": warmup,
    }
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": "10.74.0.0/16"}},
                "Subnet": {
                    "Type": "AWS::EC2::Subnet",
                    "Properties": {
                        "VpcId": {"Ref": "Vpc"},
                        "CidrBlock": "10.74.0.0/20",
                        "AvailabilityZone": {"Fn::Select": [0, {"Fn::GetAZs": ""}]},
                    },
                },
                "InstanceRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "ec2.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                        "ManagedPolicyArns": [
                            {
                                "Fn::Sub": (
                                    "arn:${AWS::Partition}:iam::aws:policy/service-role/"
                                    "AmazonEC2ContainerServiceforEC2Role"
                                )
                            }
                        ],
                    },
                },
                "InstanceProfile": {
                    "Type": "AWS::IAM::InstanceProfile",
                    "Properties": {"Roles": [{"Ref": "InstanceRole"}]},
                },
                "LaunchTemplateA": {
                    "Type": "AWS::EC2::LaunchTemplate",
                    "Properties": {
                        "LaunchTemplateData": {
                            "ImageId": f"{{{{resolve:ssm:{_AMI_PARAM}}}}}",
                            "InstanceType": "t3.micro",
                            "IamInstanceProfile": {"Arn": {"Fn::GetAtt": ["InstanceProfile", "Arn"]}},
                        }
                    },
                },
                "LaunchTemplateB": {
                    "Type": "AWS::EC2::LaunchTemplate",
                    "Properties": {
                        "LaunchTemplateData": {
                            "ImageId": f"{{{{resolve:ssm:{_AMI_PARAM}}}}}",
                            "InstanceType": "t3.micro",
                            "IamInstanceProfile": {"Arn": {"Fn::GetAtt": ["InstanceProfile", "Arn"]}},
                        }
                    },
                },
                "AsgA": {
                    "Type": "AWS::AutoScaling::AutoScalingGroup",
                    "Properties": {
                        "LaunchTemplate": {
                            "LaunchTemplateId": {"Ref": "LaunchTemplateA"},
                            "Version": {"Fn::GetAtt": ["LaunchTemplateA", "LatestVersionNumber"]},
                        },
                        "MinSize": "0",
                        "MaxSize": "1",
                        "DesiredCapacity": "0",
                        "VPCZoneIdentifier": [{"Ref": "Subnet"}],
                    },
                },
                "AsgB": {
                    "Type": "AWS::AutoScaling::AutoScalingGroup",
                    "Properties": {
                        "LaunchTemplate": {
                            "LaunchTemplateId": {"Ref": "LaunchTemplateB"},
                            "Version": {"Fn::GetAtt": ["LaunchTemplateB", "LatestVersionNumber"]},
                        },
                        "MinSize": "0",
                        "MaxSize": "1",
                        "DesiredCapacity": "0",
                        "VPCZoneIdentifier": [{"Ref": "Subnet"}],
                    },
                },
                "CapacityProvider": {
                    "Type": "AWS::ECS::CapacityProvider",
                    # Name is create-only, so pointing it at AsgB with a new Name replaces it.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {
                        "Name": cp_name,
                        "AutoScalingGroupProvider": {
                            "AutoScalingGroupArn": {"Ref": asg_logical},
                            "ManagedScaling": managed_scaling,
                            "ManagedTerminationProtection": "DISABLED",
                        },
                        "Tags": _TAGS,
                    },
                },
            },
            "Outputs": {
                # The type declares no GetAtt-able attribute; Ref returns the Name.
                "CapacityProviderRef": {"Value": {"Ref": "CapacityProvider"}},
            },
        }
    )


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:deploy",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A CloudFormation capacity provider's managed-scaling settings read back as templated.

    Turning managed scaling on updates it in place; a new Name and Auto Scaling group replaces
    it under UpdateReplacePolicy Retain, and the stack delete leaves the replacement INACTIVE.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ecs-capacityprovider.html
    https://docs.aws.amazon.com/AmazonECS/latest/developerguide/asg-capacity-providers.html
    """
    cfn = ctx.client("cloudformation")
    ecs = ctx.client("ecs")
    first = ctx.unique_name("sim2real-cfncp-a-")
    second = ctx.unique_name("sim2real-cfncp-b-")
    stack_name = ctx.unique_name("sim2real-cfncp-stack-")
    ref = {"stack": stack_name}

    # The replaced provider is retained, so it outlives the stack and needs its own teardown.
    ctx.on_cleanup(lambda: _delete_provider(ecs, first))
    ctx.on_cleanup(lambda: _teardown_stack(cfn, ref))

    # ---- 1. create: managed scaling off, pointed at AsgA
    ref["stack"] = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(first, "AsgA", _SCALING_OFF),
        Tags=_TAGS,
        Capabilities=["CAPABILITY_IAM"],
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["CapacityProvider"] == first, (
        "physical id is the capacity provider Name"
    )
    assert _outputs(stack)["CapacityProviderRef"] == first, "Ref is the capacity provider Name"
    partition = ref["stack"].split(":")[1]
    first_arn = f"arn:{partition}:ecs:{ctx.region}:{ctx.account}:capacity-provider/{first}"
    asg_a_name = _physical_ids(cfn, ref["stack"])["AsgA"]
    _assert_provider(ctx, ecs, first, first_arn, asg_a_name, _SCALING_OFF)

    # ---- 2. in-place: managed scaling turned on, same provider, same Auto Scaling group
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"],
        TemplateBody=_template(first, "AsgA", _SCALING_ON),
        Tags=_TAGS,
        Capabilities=["CAPABILITY_IAM"],
    )
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["CapacityProvider"] == first, "an in-place update keeps it"
    _assert_in_place(_rows(_events(cfn, ref["stack"]), seen, "CapacityProvider"), first)
    _assert_provider(ctx, ecs, first, first_arn, asg_a_name, _SCALING_ON)

    # ---- 3. replacement: a new Name pointed at AsgB, the old provider retained ACTIVE
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"],
        TemplateBody=_template(second, "AsgB", _SCALING_ON),
        Tags=_TAGS,
        Capabilities=["CAPABILITY_IAM"],
    )
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["CapacityProvider"] == second, (
        "the stack tracks the new provider"
    )
    _assert_replaced_and_retained(
        _rows(_events(cfn, ref["stack"]), seen, "CapacityProvider"), first, second
    )
    assert _outputs(stack)["CapacityProviderRef"] == second, "Ref follows the replacement"
    second_arn = f"arn:{partition}:ecs:{ctx.region}:{ctx.account}:capacity-provider/{second}"
    asg_b_name = _physical_ids(cfn, ref["stack"])["AsgB"]
    _assert_provider(ctx, ecs, second, second_arn, asg_b_name, _SCALING_ON)
    # The retained provider is untouched by the replacement.
    _assert_provider(ctx, ecs, first, first_arn, asg_a_name, _SCALING_ON)

    # ---- 4. delete: the replacement goes INACTIVE; the retained provider stays ACTIVE
    _delete_stack(ctx, cfn, ref["stack"])
    gone = _poll(
        ctx,
        lambda: _describe_one(ecs, second),
        lambda d: d["status"] == "INACTIVE",
        f"capacity provider {second} to reach INACTIVE after the stack delete",
    )
    got = (gone["name"], gone["capacityProviderArn"], gone["status"])
    want = (second, second_arn, "INACTIVE")
    assert got == want, f"DescribeCapacityProviders after the stack delete: {got!r}, expected {want!r}"
    still = _describe_one(ecs, first)
    assert still["status"] == "ACTIVE", (
        f"the retained provider {first!r} reports {still['status']!r} after the stack delete, "
        f"expected 'ACTIVE'"
    )


def _describe_one(ecs, name: str) -> dict:
    resp = ecs.describe_capacity_providers(capacityProviders=[name], include=["TAGS"])
    (provider,) = resp["capacityProviders"]
    return provider


def _assert_provider(ctx, ecs, name: str, arn: str, asg_name: str, scaling: tuple) -> None:
    """DescribeCapacityProviders reports the template's provider exactly, once converged."""
    status, target, min_step, max_step, warmup = scaling
    want_scaling = {
        "status": status,
        "targetCapacity": target,
        "minimumScalingStepSize": min_step,
        "maximumScalingStepSize": max_step,
        "instanceWarmupPeriod": warmup,
    }

    def _read() -> dict:
        p = _describe_one(ecs, name)
        tags_map = {t["key"]: t["value"] for t in p.get("tags", []) if not t["key"].startswith("aws:")}
        asg_provider = p["autoScalingGroupProvider"]
        return {
            "name": p["name"],
            "capacityProviderArn": p["capacityProviderArn"],
            "status": p["status"],
            "asgTail": asg_provider["autoScalingGroupArn"].rsplit(":", 1)[-1],
            "managedScaling": asg_provider.get("managedScaling"),
            "managedTerminationProtection": asg_provider["managedTerminationProtection"],
            "tags": tags_map,
        }

    asg_tail = f"autoScalingGroupName/{asg_name}"
    want = {
        "name": name,
        "capacityProviderArn": arn,
        "status": "ACTIVE",
        "asgTail": asg_tail,
        "managedScaling": want_scaling,
        "managedTerminationProtection": "DISABLED",
        "tags": {"sim2real": CHECK},
    }
    got = _poll(ctx, _read, lambda d: d == want, f"capacity provider {name} as templated")
    assert got == want, f"DescribeCapacityProviders {name}: {got!r}, expected {want!r}"


def _delete_provider(ecs, name: str) -> None:
    """Delete the retained capacity provider; one already gone or deleting is done."""
    try:
        ecs.delete_capacity_provider(capacityProvider=name)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code in ("ClientException",) and "not found" in exc.response["Error"]["Message"].lower():
            return
        raise


# ===== helpers =====


def _budget_s(ctx, cap_s):
    left = None if ctx is None else ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    left = None if ctx is None else ctx.time_left()
    return left is not None and left <= 6.0


def _settle(ctx, cfn, stack_id: str) -> dict:
    timeout = _budget_s(ctx, _STACK_CAP_S)
    deadline = time.monotonic() + timeout
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {stack_id} was {stack['StackStatus']}")
            raise AssertionError(
                f"stack {stack_id} still {stack['StackStatus']!r} after {timeout:.0f}s"
            )
        time.sleep(_POLL_S)


def _expect(cfn, stack: dict, want: str) -> None:
    if stack["StackStatus"] == want:
        return
    failed = [
        (e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
        for e in _events(cfn, stack["StackId"])
        if e["ResourceStatus"].endswith("_FAILED")
    ]
    raise AssertionError(
        f"stack ended {stack['StackStatus']!r} ({stack.get('StackStatusReason')!r}), expected "
        f"{want!r}; failed events: {failed!r}"
    )


def _events(cfn, stack_id: str) -> list[dict]:
    events: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return list(reversed(events))


def _rows(events: list[dict], seen: set[str], logical_id: str) -> list[tuple]:
    return [
        (e["ResourceStatus"], e.get("ResourceStatusReason"), e.get("PhysicalResourceId"))
        for e in events
        if e["EventId"] not in seen and e["LogicalResourceId"] == logical_id
    ]


def _assert_in_place(rows: list[tuple], physical_id: str) -> None:
    statuses = [status for status, _, _ in rows]
    assert statuses == ["UPDATE_IN_PROGRESS", "UPDATE_COMPLETE"], (
        f"CapacityProvider must update in place with no replacement, its events were {rows!r}"
    )
    assert rows[-1][2] == physical_id, (
        f"CapacityProvider must complete its update on {physical_id!r}, its events were {rows!r}"
    )


def _assert_replaced_and_retained(rows: list[tuple], old_id: str, new_id: str) -> None:
    statuses = [(status, reason) for status, reason, _ in rows]
    assert (
        "UPDATE_IN_PROGRESS",
        "Requested update requires the creation of a new physical resource; hence creating one.",
    ) in statuses, f"CapacityProvider must announce its replacement, its events were {rows!r}"
    assert ("UPDATE_COMPLETE", new_id) in [(s, pid) for s, _, pid in rows], (
        f"CapacityProvider must complete as the new physical id {new_id!r}, its events were {rows!r}"
    )
    old_rows = [(status, pid) for status, _, pid in rows if status.startswith("DELETE_")]
    assert old_rows == [("DELETE_SKIPPED", old_id)], (
        f"UpdateReplacePolicy Retain must skip deleting the replaced {old_id!r}, the delete events "
        f"of CapacityProvider were {old_rows!r}"
    )


def _physical_ids(cfn, stack_id: str) -> dict[str, str]:
    return {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    }


def _outputs(stack: dict) -> dict[str, str]:
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _delete_stack(ctx, cfn, stack_id: str) -> None:
    cfn.delete_stack(StackName=stack_id)
    _expect(cfn, _settle(ctx, cfn, stack_id), "DELETE_COMPLETE")


def _teardown_stack(cfn, ref: dict) -> None:
    try:
        stack = cfn.describe_stacks(StackName=ref["stack"])["Stacks"][0]
    except ClientError as exc:
        if exc.response["Error"]["Message"] == f"Stack with id {ref['stack']} does not exist":
            return
        raise
    if stack["StackStatus"] == "DELETE_COMPLETE":
        return
    if stack["StackStatus"].endswith("_IN_PROGRESS"):
        stack = _settle(None, cfn, stack["StackId"])
    _delete_stack(None, cfn, stack["StackId"])


def _poll(ctx, read, done, what: str, cap_s: float = _CONVERGE_CAP_S):
    timeout = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout
    while True:
        value = read()
        if done(value):
            return value
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while waiting for {what}; last {value!r}")
            raise AssertionError(f"{what} not reached after {timeout:.0f}s; last {value!r}")
        time.sleep(_POLL_S)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
