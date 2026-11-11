"""instance-attach-detach-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError


from behavioral_harness import tags


CHECK = "instance-attach-detach-lifecycle"
GROUP = 'overly-permissive'
SERVICES = ['autoscaling']


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AttachInstances -> DescribeAutoScalingInstances(member) -> DetachInstances ->
    DescribeAutoScalingInstances(absent)."""
    as_ = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")

    def _poll_until(probe, pred, timeout_s=120, interval_s=3, description="condition"):
        import time
        deadline = time.monotonic() + timeout_s
        last = None
        while time.monotonic() < deadline:
            last = probe()
            if pred(last):
                return last
            time.sleep(interval_s)
        raise AssertionError(f"{description} not met within {timeout_s}s; last result: {last!r}")

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

    def _describe_asg_instances(instance_ids):
        return as_.describe_auto_scaling_instances(InstanceIds=instance_ids).get(
            "AutoScalingInstances", []
        )

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
        }
        params.update(kwargs)
        as_.create_auto_scaling_group(**params)
        ctx.on_cleanup(
            lambda n=asg_name: as_.delete_auto_scaling_group(
                AutoScalingGroupName=n, ForceDelete=True
            )
        )
        return asg_name

    def _launch_standalone_instance():
        resp = ec2.run_instances(
            ImageId=_image_id(),
            InstanceType="t3.micro",
            MinCount=1,
            MaxCount=1,
            SubnetId=_subnet_ids()[0],
            TagSpecifications=[
                {
                    "ResourceType": "instance",
                    "Tags": [
                        {"Key": "sim2real:managed", "Value": "true"},
                        {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
                    ],
                }
            ],
        )
        instance_id = resp["Instances"][0]["InstanceId"]
        ctx.on_cleanup(lambda i=instance_id: ec2.terminate_instances(InstanceIds=[i]))
        ec2.get_waiter("instance_running").wait(
            InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 60}
        )
        return instance_id

    def _error(fn):
        try:
            result = fn()
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
        raise AssertionError(
            f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}"
        )

    name = _make_asg(min_size=0, max_size=3, desired_capacity=0)
    instance_id = _launch_standalone_instance()

    as_.attach_instances(AutoScalingGroupName=name, InstanceIds=[instance_id])

    attached = _poll_until(
        lambda: _describe_asg_instances([instance_id]),
        lambda insts: len(insts) == 1
        and insts[0]["AutoScalingGroupName"] == name
        and insts[0]["LifecycleState"] == "InService",
        timeout_s=120,
        interval_s=3,
        description=f"instance {instance_id} InService in {name}",
    )
    assert attached[0]["LifecycleState"] == "InService"
    group = _describe_group(name)
    assert group["DesiredCapacity"] == 1, "AttachInstances must bump DesiredCapacity"

    # Overly-permissive guard: DetachInstances for an instance that is NOT a member of the
    # group must fail rather than silently no-op.
    fake_id = "i-" + "0" * 17
    code, message = _error(
        lambda: as_.detach_instances(
            AutoScalingGroupName=name, InstanceIds=[fake_id], ShouldDecrementDesiredCapacity=False
        )
    )
    assert code == "ValidationError", f"expected ValidationError detaching a non-member instance, got {code!r}"
    expected = f"The instance {fake_id} is not part of Auto Scaling group {name}."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    as_.detach_instances(
        AutoScalingGroupName=name, InstanceIds=[instance_id], ShouldDecrementDesiredCapacity=True
    )
    _poll_until(
        lambda: _describe_asg_instances([instance_id]),
        lambda insts: insts == [],
        timeout_s=60,
        interval_s=2,
        description=f"instance {instance_id} detached from {name}",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
