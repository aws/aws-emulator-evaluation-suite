"""cfn-ecs-capacity-provider-managed-termination-protection-without-scale-in-protection-rejected."""

from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = (
    "cfn-ecs-capacity-provider-managed-termination-protection-without-scale-in-protection-rejected"
)
GROUP = "deploy"
SERVICES = ["cloudformation", "ecs"]

_STACK_CAP_S = 600.0
_POLL_S = 3.0

_AMI_PARAM = "/aws/service/ecs/optimized-ami/amazon-linux-2/recommended/image_id"

#: CloudFormation wraps a failed resource-handler call in one fixed sentence shape.
_HANDLER_FAILURE = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)
#: The AWS request id inside the wrapped ECS error, which differs on every call.
_REQUEST_ID = re.compile(r"Request ID: [0-9a-f-]{36}\)")


def _template(cp_name: str, asg_name: str, scale_in_protected: bool) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": "10.83.0.0/16"}},
                "Subnet": {
                    "Type": "AWS::EC2::Subnet",
                    "Properties": {
                        "VpcId": {"Ref": "Vpc"},
                        "CidrBlock": "10.83.0.0/20",
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
                "LaunchTemplate": {
                    "Type": "AWS::EC2::LaunchTemplate",
                    "Properties": {
                        "LaunchTemplateData": {
                            "ImageId": f"{{{{resolve:ssm:{_AMI_PARAM}}}}}",
                            "InstanceType": "t3.micro",
                            "IamInstanceProfile": {"Arn": {"Fn::GetAtt": ["InstanceProfile", "Arn"]}},
                        }
                    },
                },
                "Asg": {
                    "Type": "AWS::AutoScaling::AutoScalingGroup",
                    "Properties": {
                        "AutoScalingGroupName": asg_name,
                        "LaunchTemplate": {
                            "LaunchTemplateId": {"Ref": "LaunchTemplate"},
                            "Version": {"Fn::GetAtt": ["LaunchTemplate", "LatestVersionNumber"]},
                        },
                        "MinSize": "0",
                        "MaxSize": "1",
                        "DesiredCapacity": "0",
                        "VPCZoneIdentifier": [{"Ref": "Subnet"}],
                        "NewInstancesProtectedFromScaleIn": scale_in_protected,
                    },
                },
                "CapacityProvider": {
                    "Type": "AWS::ECS::CapacityProvider",
                    "Properties": {
                        "Name": cp_name,
                        "AutoScalingGroupProvider": {
                            "AutoScalingGroupArn": {"Ref": "Asg"},
                            "ManagedScaling": {"Status": "ENABLED", "TargetCapacity": 100},
                            "ManagedTerminationProtection": "ENABLED",
                        },
                    },
                },
            },
            "Outputs": {"CapacityProviderRef": {"Value": {"Ref": "CapacityProvider"}}},
        }
    )


def _own_providers(ecs, name: str) -> list[dict]:
    """Every capacity provider named *name*, from an unfiltered, fully paged list."""
    found: list[dict] = []
    token = None
    while True:
        kw = {"maxResults": 10, **({"nextToken": token} if token else {})}
        resp = ecs.describe_capacity_providers(**kw)
        found.extend(p for p in resp["capacityProviders"] if p["name"] == name)
        token = resp.get("nextToken")
        if not token:
            return found


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Turning on managed termination protection without the Auto Scaling group's own scale-in
    protection fails the capacity provider's creation; with scale-in protection it succeeds.

    Reference: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/asg-capacity-providers.html
    """
    cfn = ctx.client("cloudformation")
    ecs = ctx.client("ecs")
    good_name = ctx.unique_name("sim2real-cfncpmt-ok-")
    good_asg = ctx.unique_name("sim2real-cfncpmt-ok-asg-")
    bad_name = ctx.unique_name("sim2real-cfncpmt-bad-")
    bad_asg = ctx.unique_name("sim2real-cfncpmt-bad-asg-")

    # Positive control: the Auto Scaling group itself carries scale-in protection.
    good_stack = ctx.unique_name("sim2real-cfncpmt-ok-stack-")
    good_ref = {"stack": good_stack}
    ctx.on_cleanup(lambda: _teardown_stack(cfn, good_ref))
    good_ref["stack"] = cfn.create_stack(
        StackName=good_stack,
        TemplateBody=_template(good_name, good_asg, True),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        Capabilities=["CAPABILITY_IAM"],
    )["StackId"]
    good_stack_obj = _settle(ctx, cfn, good_ref["stack"])
    _expect(cfn, good_stack_obj, "CREATE_COMPLETE")
    provider = ecs.describe_capacity_providers(
        capacityProviders=[good_name]
    )["capacityProviders"][0]
    assert provider["status"] == "ACTIVE", (
        f"the control provider {good_name!r} reports {provider['status']!r}, expected 'ACTIVE'"
    )
    assert provider["autoScalingGroupProvider"]["managedTerminationProtection"] == "ENABLED", (
        "the control provider, on a scale-in-protected group, must honour "
        f"managedTerminationProtection: {provider['autoScalingGroupProvider']!r}"
    )

    # Break exactly one thing: the same template, the Auto Scaling group left unprotected.
    bad_stack = ctx.unique_name("sim2real-cfncpmt-bad-stack-")
    bad_ref = {"stack": bad_stack}
    ctx.on_cleanup(lambda: _teardown_stack(cfn, bad_ref))
    bad_ref["stack"] = cfn.create_stack(
        StackName=bad_stack,
        TemplateBody=_template(bad_name, bad_asg, False),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        Capabilities=["CAPABILITY_IAM"],
    )["StackId"]
    bad_stack_obj = _settle(ctx, cfn, bad_ref["stack"])
    assert bad_stack_obj["StackStatus"] == "ROLLBACK_COMPLETE", (
        f"stack with an unprotected Auto Scaling group ended {bad_stack_obj['StackStatus']!r}, "
        f"expected 'ROLLBACK_COMPLETE'"
    )
    reason = _resource_failure_reason(cfn, bad_ref["stack"], "CapacityProvider")
    message, code = _parse_handler_failure(reason)
    raw_message = message
    message = _REQUEST_ID.sub("Request ID: <redacted>)", message)
    want_message = (
        "Invalid request provided: CreateCapacityProvider error: The managed termination "
        "protection setting for the capacity provider is invalid. To enable managed termination "
        "protection for a capacity provider, the Auto Scaling group must have instance protection "
        "from scale in enabled. (Service: Ecs, Status Code: 400, Request ID: <redacted>) "
        "(SDK Attempt Count: 1)"
    )
    assert (code, message) == ("InvalidRequest", want_message), (
        f"CapacityProvider rejection was {(code, raw_message)!r}"
    )

    # The effect is absent: no capacity provider named bad_name was ever left behind.
    left = _own_providers(ecs, bad_name)
    assert left == [], f"a rejected create still left capacity provider(s) {left!r}"


def _resource_failure_reason(cfn, stack_id: str, logical_id: str) -> str:
    events = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    failures = [
        e["ResourceStatusReason"]
        for e in reversed(events)
        if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == "CREATE_FAILED"
    ]
    assert len(failures) == 1, f"{logical_id} CREATE_FAILED events: {failures!r}, expected exactly 1"
    return failures[0]


def _parse_handler_failure(reason: str) -> tuple[str, str]:
    failure = _HANDLER_FAILURE.match(reason)
    assert failure is not None, f"not a resource-handler failure reason: {reason!r}"
    return failure["message"], failure["code"]


def _settle(ctx, cfn, stack_id: str) -> dict:
    deadline = time.monotonic() + _STACK_CAP_S
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"stack {stack_id} still {stack['StackStatus']!r} after {_STACK_CAP_S:.0f}s"
            )
        time.sleep(_POLL_S)


def _expect(cfn, stack: dict, want: str) -> None:
    if stack["StackStatus"] == want:
        return
    raise AssertionError(
        f"stack ended {stack['StackStatus']!r} ({stack.get('StackStatusReason')!r}), expected {want!r}"
    )


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
    if stack["StackStatus"] in ("DELETE_COMPLETE", "ROLLBACK_COMPLETE"):
        if stack["StackStatus"] == "ROLLBACK_COMPLETE":
            _delete_stack(None, cfn, stack["StackId"])
        return
    if stack["StackStatus"].endswith("_IN_PROGRESS"):
        stack = _settle(None, cfn, stack["StackId"])
        if stack["StackStatus"] == "ROLLBACK_COMPLETE":
            _delete_stack(None, cfn, stack["StackId"])
            return
    _delete_stack(None, cfn, stack["StackId"])


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
