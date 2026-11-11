"""asg-reflects-launch-template."""
from __future__ import annotations


from behavioral_harness import tags

CHECK = "asg-reflects-launch-template"
GROUP = 'group-lifecycle'
SERVICES = ['autoscaling']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An ASG created from a launch template by NAME resolves that name to the template's id, and
    keeps tracking it as a live pointer: adding a new template version must not rebase or fork the
    group's reference ($Latest is not resolved to a snapshot at create time)."""
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

    def _describe_group(name):
        groups = as_.describe_auto_scaling_groups(AutoScalingGroupNames=[name]).get(
            "AutoScalingGroups", []
        )
        return groups[0] if groups else None

    lt_name = ctx.unique_name("sim2real-behav-as-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": _image_id(), "InstanceType": "t3.small"},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}
        ],
    )
    ctx.on_cleanup(lambda n=lt_name: ec2.delete_launch_template(LaunchTemplateName=n))

    try:
        lt = ec2.describe_launch_templates(LaunchTemplateNames=[lt_name])["LaunchTemplates"][0]
    except Exception:
        lt = None
    assert lt is not None, "launch template must be describable after creation"

    name = ctx.unique_name("sim2real-behav-as-grp-")
    as_.create_auto_scaling_group(
        AutoScalingGroupName=name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=0,
        MaxSize=1,
        DesiredCapacity=0,
        VPCZoneIdentifier=",".join(_subnet_ids()),
        HealthCheckGracePeriod=0,
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": False}],
    )
    ctx.on_cleanup(
        lambda n=name: as_.delete_auto_scaling_group(AutoScalingGroupName=n, ForceDelete=True)
    )

    group = _describe_group(name)
    spec = group.get("LaunchTemplate")
    assert spec, "group created from a launch template must report LaunchTemplate"
    assert spec["LaunchTemplateName"] == lt_name
    assert spec["LaunchTemplateId"] == lt["LaunchTemplateId"], "group must resolve the template id"
    assert spec["Version"] == "$Latest", f"requested version must be preserved, got {spec.get('Version')}"
    # A launch-template group must NOT report a launch configuration.
    assert "LaunchConfigurationName" not in group, "launch-template group must not expose LaunchConfigurationName"

    # $Latest is a live pointer, not a value resolved and snapshotted at create time: a new template
    # version must not rebase the group's reported Version or fork it onto a different template id.
    ec2.create_launch_template_version(
        LaunchTemplateName=lt_name,
        SourceVersion="1",
        LaunchTemplateData={"ImageId": _image_id(), "InstanceType": "t3.medium"},
    )
    group_after = _describe_group(name)
    spec_after = group_after.get("LaunchTemplate") if group_after else None
    assert spec_after, "group must still report LaunchTemplate after a new template version is created"
    assert spec_after["Version"] == "$Latest", (
        f"$Latest must remain a live pointer, not resolve to a snapshot; got {spec_after.get('Version')}"
    )
    assert spec_after["LaunchTemplateId"] == lt["LaunchTemplateId"], (
        "a new template version must not fork the group onto a different template id"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
