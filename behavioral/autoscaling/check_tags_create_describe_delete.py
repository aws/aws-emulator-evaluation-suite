"""tags-create-describe-delete."""
from __future__ import annotations


from behavioral_harness import tags


CHECK = "tags-create-describe-delete"
GROUP = 'tags'
SERVICES = ['autoscaling']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateOrUpdateTags/DeleteTags round-trip a tag through DescribeTags."""
    as_ = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")

    def _image_id():
        param = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
        try:
            return ssm.get_parameter(Name=param)["Parameter"]["Value"]
        except Exception:
            imgs = sorted(
                ec2.describe_images(
                    Owners=["amazon"],
                    Filters=[
                        {"Name": "name", "Values": ["al2023-ami-kernel-default-x86_64*"]},
                        {"Name": "state", "Values": ["available"]},
                    ],
                ).get("Images", []),
                key=lambda i: i.get("CreationDate", ""),
            )
            if not imgs:
                raise AssertionError("no Amazon Linux 2023 AMI available in this region")
            return imgs[-1]["ImageId"]

    def _subnet_ids():
        subnets = ec2.describe_subnets(
            Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
        ).get("Subnets", [])
        if not subnets:
            raise AssertionError(f"the run's shared network subnets {ctx.network().subnet_ids} are not visible")
        return [s["SubnetId"] for s in sorted(subnets, key=lambda s: s["AvailabilityZone"])[:2]]

    def _make_lt(instance_type="t3.micro"):
        lt_name = ctx.unique_name("sim2real-behav-as-lt-")
        ec2.create_launch_template(
            LaunchTemplateName=lt_name,
            LaunchTemplateData={"ImageId": _image_id(), "InstanceType": instance_type},
        )
        ctx.on_cleanup(lambda n=lt_name: ec2.delete_launch_template(LaunchTemplateName=n))
        return lt_name

    def _make_asg(min_size=0, max_size=1, desired_capacity=0, launch_template_name=None, **kwargs):
        if launch_template_name is None:
            launch_template_name = _make_lt()
        asg_name = ctx.unique_name("sim2real-behav-as-grp-")
        params = {
            "AutoScalingGroupName": asg_name,
            "LaunchTemplate": {"LaunchTemplateName": launch_template_name, "Version": "$Latest"},
            "MinSize": min_size,
            "MaxSize": max_size,
            "DesiredCapacity": desired_capacity,
            "VPCZoneIdentifier": ",".join(_subnet_ids()),
            "HealthCheckGracePeriod": 0,
            "Tags": [{"Key": "sim2real:managed", "Value": "true"}],
        }
        params.update(kwargs)
        as_.create_auto_scaling_group(**params)
        ctx.on_cleanup(
            lambda n=asg_name: as_.delete_auto_scaling_group(
                AutoScalingGroupName=n, ForceDelete=True
            )
        )
        return asg_name

    name = _make_asg(min_size=0, max_size=1, desired_capacity=0)
    tag = {
        "ResourceId": name,
        "ResourceType": "auto-scaling-group",
        "Key": "fidelity-check",
        "Value": "true",
        "PropagateAtLaunch": False,
    }

    as_.create_or_update_tags(Tags=[tag])

    resp = as_.describe_tags(Filters=[{"Name": "auto-scaling-group", "Values": [name]}])
    matched = [t for t in resp["Tags"] if t["Key"] == "fidelity-check"]
    assert matched and matched[0]["Value"] == "true", f"expected tag value 'true', got {matched}"

    as_.delete_tags(Tags=[tag])
    resp = as_.describe_tags(Filters=[{"Name": "auto-scaling-group", "Values": [name]}])
    matched = [t for t in resp["Tags"] if t["Key"] == "fidelity-check"]
    assert matched == [], "deleted tag must no longer be returned"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
