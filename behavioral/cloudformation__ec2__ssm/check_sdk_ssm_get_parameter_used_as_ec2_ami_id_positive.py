"""sdk-ssm-get-parameter-used-as-ec2-ami-id-positive."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "sdk-ssm-get-parameter-used-as-ec2-ami-id-positive"
GROUP = "arn-resolution"
SERVICES = ["cloudformation", "ec2", "ssm"]

_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"


@tags("axis:happy-path", "cap:c1", "cap:c4", "cap:c5", "concern:e2e", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An AMI ID fetched from a public AWS-managed SSM parameter is a real, launchable AMI:
    launching an EC2 instance with that exact ImageId succeeds and describe_instances/
    describe_images resolve back to the same AMI."""
    ssm = ctx.client("ssm")
    ami_id = ssm.get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    assert ami_id.startswith("ami-"), f"expected an ami-* id from {_AL2023_AMI_PARAM}, got {ami_id!r}"

    ec2 = ctx.client("ec2")
    images = ec2.describe_images(ImageIds=[ami_id])["Images"]
    assert len(images) == 1, f"expected exactly one image for {ami_id}, describe_images returned {len(images)}"
    assert images[0]["ImageId"] == ami_id, f"expected ImageId {ami_id}, describe_images returned {images[0]['ImageId']}"

    instance_id = _launch_instance(ctx, ami_id)
    desc = ec2.describe_instances(InstanceIds=[instance_id])
    launched_ami = desc["Reservations"][0]["Instances"][0]["ImageId"]
    assert launched_ami == ami_id, (
        f"expected instance {instance_id} to have launched with ImageId {ami_id}, "
        f"describe_instances reports {launched_ami}"
    )


def _tag_spec(ctx, resource_type: str, name: str):
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}]


def _default_subnet(ctx) -> str:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to launch a test EC2 instance")
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpcs[0]["VpcId"]]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets available")
    return subnets[0]["SubnetId"]


def _launch_instance(ctx, ami_id: str):
    ec2 = ctx.client("ec2")
    subnet_id = _default_subnet(ctx)
    resp = ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_id,
        TagSpecifications=_tag_spec(ctx, "instance", ctx.unique_name("sim2real-ami-param-")),
    )
    instance_id = resp["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    return instance_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
