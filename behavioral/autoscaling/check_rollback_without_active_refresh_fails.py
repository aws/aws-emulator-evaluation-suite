"""rollback-without-active-refresh-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "rollback-without-active-refresh-fails"
GROUP = 'error-semantics'
SERVICES = ['autoscaling']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RollbackInstanceRefresh on a group with no refresh history fails with IrreversibleInstanceRefresh.

    Empirically real AWS reports IrreversibleInstanceRefresh (not
    ActiveInstanceRefreshNotFoundFault) for a group that never had a refresh.
    """
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

    try:
        as_.rollback_instance_refresh(AutoScalingGroupName=name)
        code = message = None
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    assert code == "IrreversibleInstanceRefresh", f"expected IrreversibleInstanceRefresh, got {code}"
    expected = ("This Auto Scaling group's launch template version isn't compatible with a rollback. "
                "Rollbacks are not supported when the Auto Scaling group uses the launch template's "
                "'$Latest' or '$Default' version.")
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Independent read at the destination: the rejected rollback must not have
    # fabricated any instance refresh record for this group.
    refreshes = as_.describe_instance_refreshes(AutoScalingGroupName=name).get(
        "InstanceRefreshes", []
    )
    assert refreshes == [], f"expected no instance refreshes to exist, found {refreshes}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
