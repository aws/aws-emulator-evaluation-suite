"""ecs-capacity-provider-without-autoscaling-permission-fails-association."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ecs-capacity-provider-without-autoscaling-permission-fails-association"
GROUP = "permission-boundary"
SERVICES = ["autoscaling", "ecs", "elbv2"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCapacityProvider from a principal denied autoscaling:CreateOrUpdateTags and
    UpdateAutoScalingGroup is rejected and leaves the ASG untouched; an unrestricted principal
    succeeds."""
    ec2 = ctx.client("ec2")
    autoscaling = ctx.client("autoscaling")
    ecs = ctx.client("ecs")
    iam = ctx.client("iam")

    _, subnet_ids, _ = _default_vpc_info(ctx)
    ami_id = _al2023_ami_id(ctx)

    lt_name = ctx.unique_name("sim2real-cp-perm-lt-")
    lt_id = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}
        ],
    )["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))

    asg_name = ctx.unique_name("sim2real-cp-perm-asg-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
        MinSize=0,
        MaxSize=1,
        DesiredCapacity=0,
        VPCZoneIdentifier=",".join(subnet_ids),
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": False}],
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_auto_scaling_group(
            AutoScalingGroupName=asg_name, ForceDelete=True
        )
    )
    asg_arn = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ][0]["AutoScalingGroupARN"]

    restricted_ecs = _restricted_ecs_client(ctx, iam)

    cp_name = ctx.unique_name("sim2real-cp-perm-provider-")
    provider_spec = {
        "autoScalingGroupArn": asg_arn,
        "managedScaling": {
            "status": "ENABLED",
            "targetCapacity": 100,
            "minimumScalingStepSize": 1,
            "maximumScalingStepSize": 1,
        },
        "managedTerminationProtection": "DISABLED",
    }

    def _delete_cp_if_exists():
        try:
            ecs.delete_capacity_provider(capacityProvider=cp_name)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in (
                "InvalidParameterException",
                "ClientException",
            ):
                raise

    # Registered before the restricted call is even attempted: if the target is over-permissive
    # and the "denied" call below unexpectedly creates the provider, it must still be reaped.
    ctx.on_cleanup(_delete_cp_if_exists)

    code, message = _error(
        lambda: restricted_ecs.create_capacity_provider(
            name=cp_name, autoScalingGroupProvider=provider_spec
        )
    )
    assert code == "AccessDeniedException", (
        f"expected AccessDeniedException when the caller lacks autoscaling permissions to bind "
        f"the ASG, got {code!r} ({message!r})"
    )
    expected_message = (
        "The capacity provider could not be created because you do not have "
        "autoscaling:CreateOrUpdateTags permissions to create tags on the Auto Scaling group."
    )
    assert message == expected_message, (
        f"AccessDeniedException message {message!r}, expected {expected_message!r}"
    )

    # effect absent: the capacity provider was never created, the ASG was never touched
    describe_resp = ecs.describe_capacity_providers(capacityProviders=[cp_name])
    assert describe_resp["capacityProviders"] == [], (
        f"capacity provider should not exist after the rejected call: {describe_resp}"
    )
    asg_tags = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ][0]["Tags"]
    assert "AmazonECSManaged" not in {t["Key"] for t in asg_tags}, (
        f"ASG should not have been tagged by a failed CreateCapacityProvider call: {asg_tags}"
    )

    # positive control: the same call, same ASG, from an unrestricted principal succeeds
    ecs.create_capacity_provider(
        name=cp_name,
        autoScalingGroupProvider=provider_spec,
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    described = ecs.describe_capacity_providers(capacityProviders=[cp_name])["capacityProviders"]
    assert len(described) == 1 and described[0]["status"] == "ACTIVE", (
        f"positive control failed to create the capacity provider: {described}"
    )


def _default_vpc_info(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC in this account/region to place the ASG's subnets")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets")
    subnet_ids = [s["SubnetId"] for s in subnets]
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    sg_id = sgs[0]["GroupId"] if sgs else None
    return vpc_id, subnet_ids, sg_id


def _al2023_ami_id(ctx):
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(
        f"expected the call to be rejected for lacking autoscaling permissions, but it "
        f"succeeded and returned {result!r}"
    )


def _restricted_ecs_client(ctx, iam):
    """An IAM user allowed to call ecs:CreateCapacityProvider / ecs:DescribeCapacityProviders
    but explicitly denied the autoscaling actions ECS needs to bind the ASG on its behalf."""
    user_name = ctx.unique_name("sim2real-cp-perm-user-")
    iam.create_user(UserName=user_name)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))
    policy_name = "sim2real-cp-perm-policy"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "ecs:CreateCapacityProvider",
                    "ecs:DescribeCapacityProviders",
                    "ecs:DeleteCapacityProvider",
                    "ecs:TagResource",
                ],
                "Resource": "*",
            },
            {"Effect": "Allow", "Action": ["autoscaling:Describe*"], "Resource": "*"},
            {
                "Effect": "Deny",
                "Action": ["autoscaling:CreateOrUpdateTags", "autoscaling:UpdateAutoScalingGroup"],
                "Resource": "*",
            },
        ],
    }
    iam.put_user_policy(
        UserName=user_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc)
    )
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=user_name, PolicyName=policy_name))
    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    ctx.on_cleanup(
        lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"])
    )

    creds = {
        "aws_access_key_id": key["AccessKeyId"],
        "aws_secret_access_key": key["SecretAccessKey"],
    }
    sts = ctx.client("sts", creds=creds)
    deadline = time.monotonic() + 30.0
    last_exc = None
    while time.monotonic() < deadline:
        try:
            sts.get_caller_identity()
            break
        except ClientError as exc:
            last_exc = exc
            time.sleep(2.0)
    else:
        raise AssertionError(f"new IAM user credentials never propagated: {last_exc}")

    return ctx.client("ecs", creds=creds)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
