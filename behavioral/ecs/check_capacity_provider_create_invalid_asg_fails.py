"""capacity-provider-create-invalid-asg-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "capacity-provider-create-invalid-asg-fails"
GROUP = 'overly-permissive'
SERVICES = ['ecs']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCapacityProvider must reject an autoScalingGroupArn that resolves to no real ASG and
    create nothing; a real zero-capacity ASG is accepted as a positive control.
    """
    ecs = ctx.client("ecs")

    # Positive control: a real ASG is accepted, so the negative below cannot
    # pass merely because CreateCapacityProvider is broken or unreachable.
    asg_arn = _create_zero_capacity_asg(ctx)
    good_name = ctx.unique_name("sim2real-behav-ecs-cp-ok-")
    ecs.create_capacity_provider(
        name=good_name,
        autoScalingGroupProvider={
            "autoScalingGroupArn": asg_arn,
            "managedScaling": {"status": "DISABLED"},
        },
    )
    ctx.on_cleanup(lambda: _delete_cp(ecs, good_name))
    _wait_cp_active(ecs, good_name)

    # Negative: an ASG ARN shaped correctly but that resolves to nothing real.
    name = ctx.unique_name("sim2real-behav-ecs-cp-")
    bogus_asg = (
        f"arn:aws:autoscaling:{ctx.region}:111122223333:autoScalingGroup:"
        f"00000000-0000-0000-0000-000000000000:autoScalingGroupName/{name}"
    )
    try:
        result = ecs.create_capacity_provider(
            name=name,
            autoScalingGroupProvider={
                "autoScalingGroupArn": bogus_asg,
                "managedScaling": {"status": "DISABLED"},
            },
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    else:
        ctx.on_cleanup(lambda: ecs.delete_capacity_provider(capacityProvider=name))
        raise AssertionError(f"CreateCapacityProvider accepted a nonexistent ASG: {result!r}")
    assert code == "ClientException", f"unexpected error code: {code}"
    assert message == (
        "The specified Auto Scaling group does not exist. Specify a valid Auto Scaling group and try again."
    ), f"unexpected message: {message!r}"

    # Effect absent: an independent read at the destination shows the
    # rejected capacity provider was never created.
    described = ecs.describe_capacity_providers(capacityProviders=[name])["capacityProviders"]
    assert described == [], f"rejected capacity provider {name} exists anyway: {described}"


_NET_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


def _private_subnet(ctx):
    """A subnet in a VPC this check creates. The zero-capacity Auto Scaling group placed in
    it launches no instance, so the subnet never holds an ENI and deletes cleanly."""
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.199.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _NET_TAGS}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    az = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.199.0.0/25",
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _NET_TAGS}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))
    return subnet_id


def _create_zero_capacity_asg(ctx):
    ec2 = ctx.client("ec2")
    autoscaling = ctx.client("autoscaling")
    ssm = ctx.client("ssm")
    subnet_id = _private_subnet(ctx)
    ami_id = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]

    lt_name = ctx.unique_name("sim2real-ecs-cpinv-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))

    asg_name = ctx.unique_name("sim2real-ecs-cpinv-asg-")
    # MinSize=MaxSize=DesiredCapacity=0: the ASG exists (and gets a real ARN) but never
    # launches an EC2 instance, so this fixture is free.
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateName": lt_name},
        MinSize=0,
        MaxSize=0,
        DesiredCapacity=0,
        VPCZoneIdentifier=subnet_id,
        NewInstancesProtectedFromScaleIn=True,
    )
    ctx.on_cleanup(lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True))

    groups = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"]
    return groups[0]["AutoScalingGroupARN"]


def _wait_cp_active(ecs, name, timeout_s=90.0):
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        described = ecs.describe_capacity_providers(capacityProviders=[name])["capacityProviders"]
        if described:
            last = described[0]["status"]
            if last == "ACTIVE":
                return
        time.sleep(3)
    raise AssertionError(f"capacity provider {name} never became ACTIVE (last status={last!r})")


def _delete_cp(ecs, name):
    try:
        ecs.delete_capacity_provider(capacityProvider=name)
    except ClientError as exc:
        # the run may have failed before the capacity provider existed
        if exc.response.get("Error", {}).get("Code") != "ClientException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
