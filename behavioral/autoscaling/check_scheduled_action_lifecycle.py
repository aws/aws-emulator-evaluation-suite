"""scheduled-action-lifecycle."""
from __future__ import annotations


from behavioral_harness import tags


CHECK = "scheduled-action-lifecycle"
GROUP = 'tags-scheduled'
SERVICES = ['autoscaling']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutScheduledUpdateGroupAction/BatchDeleteScheduledAction round-trip through DescribeScheduledActions."""
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
            TagSpecifications=[
                {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}
            ],
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
            "Tags": [{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
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
    action_name = ctx.unique_name("sim2real-behav-as-sched-")

    as_.put_scheduled_update_group_action(
        AutoScalingGroupName=name,
        ScheduledActionName=action_name,
        Recurrence="0 12 * * *",
        MinSize=0,
        MaxSize=3,
        DesiredCapacity=1,
    )

    resp = as_.describe_scheduled_actions(AutoScalingGroupName=name, ScheduledActionNames=[action_name])
    actions = resp["ScheduledUpdateGroupActions"]
    assert len(actions) == 1, f"expected exactly one scheduled action, got {actions!r}"
    action = actions[0]
    assert action["Recurrence"] == "0 12 * * *", f"Recurrence did not round-trip: {action!r}"
    assert action["MinSize"] == 0, f"MinSize did not round-trip: {action!r}"
    assert action["MaxSize"] == 3, f"MaxSize did not round-trip: {action!r}"
    assert action["DesiredCapacity"] == 1, f"DesiredCapacity did not round-trip: {action!r}"

    del_resp = as_.batch_delete_scheduled_action(
        AutoScalingGroupName=name, ScheduledActionNames=[action_name]
    )
    assert del_resp["FailedScheduledActions"] == [], (
        f"expected no delete failures, got {del_resp['FailedScheduledActions']!r}"
    )

    resp = as_.describe_scheduled_actions(AutoScalingGroupName=name, ScheduledActionNames=[action_name])
    remaining = resp["ScheduledUpdateGroupActions"]
    assert remaining == [], f"scheduled action still present after delete: {remaining!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
