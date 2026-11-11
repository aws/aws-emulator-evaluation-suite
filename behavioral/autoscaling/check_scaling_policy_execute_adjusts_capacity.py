"""scaling-policy-execute-adjusts-capacity."""
from __future__ import annotations


from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "scaling-policy-execute-adjusts-capacity"
GROUP = 'scaling-policy'
SERVICES = ['autoscaling']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ExecutePolicy on a simple-scaling policy with a +1 adjustment actually raises DesiredCapacity
    -- and a second real instance reaches InService, not just the control-plane field."""
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

    def _group_instances(name):
        g = _describe_group(name)
        return g.get("Instances", []) if g else []

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

    def _teardown_asg(name):
        # Billable-leak guard: drain min/max/desired to zero, THEN ForceDelete.
        # A gone group is clean; an in-progress scaling activity is retried every 2 s for 60 s.
        import time

        deadline = time.monotonic() + 60.0
        while True:
            try:
                as_.update_auto_scaling_group(
                    AutoScalingGroupName=name, MinSize=0, MaxSize=0, DesiredCapacity=0
                )
                break
            except ClientError as err:
                error = err.response["Error"]
                if error["Code"] == "ValidationError" and "not found" in error.get("Message", ""):
                    return
                if error["Code"] not in ("ScalingActivityInProgress", "ResourceContention") or (
                    time.monotonic() >= deadline
                ):
                    raise
            time.sleep(2)
        as_.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)

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
        ctx.on_cleanup(lambda n=asg_name: _teardown_asg(n))
        return asg_name

    def _wait_for_in_service(name, count, timeout_s=420, interval_s=5):
        def _pred(ins):
            return (
                bool(ins)
                and len(ins) == count
                and all(i.get("LifecycleState") == "InService" for i in ins)
            )
        return _poll_until(lambda: _group_instances(name), _pred, timeout_s, interval_s)

    def _wait_for_group_field(name, predicate, timeout_s=120, interval_s=3):
        return _poll_until(lambda: _describe_group(name), predicate, timeout_s, interval_s)

    name = _make_asg(min_size=0, max_size=5, desired_capacity=1)
    _wait_for_in_service(name, 1, timeout_s=420, interval_s=5)
    policy_name = ctx.unique_name("sim2real-behav-as-pol-")

    resp = as_.put_scaling_policy(
        AutoScalingGroupName=name,
        PolicyName=policy_name,
        PolicyType="SimpleScaling",
        AdjustmentType="ChangeInCapacity",
        ScalingAdjustment=1,
        Cooldown=0,
    )
    ctx.on_cleanup(lambda: as_.delete_policy(AutoScalingGroupName=name, PolicyName=policy_name))
    assert resp["PolicyARN"], f"put_scaling_policy must return a non-empty PolicyARN, got {resp!r}"

    as_.execute_policy(AutoScalingGroupName=name, PolicyName=policy_name, HonorCooldown=False)

    # The adjustment is applied asynchronously by a scaling activity; give it room.
    group = _wait_for_group_field(name, lambda g: g is not None and g["DesiredCapacity"] == 2,
                                    timeout_s=300, interval_s=5)
    assert group["DesiredCapacity"] == 2, "ExecutePolicy(+1) must raise DesiredCapacity from 1 to 2"

    # DesiredCapacity is only the control-plane record of the decision; a target could set that
    # field without ever launching anything. Demand the real second instance too.
    grown = _wait_for_in_service(name, 2, timeout_s=420, interval_s=5)
    assert len(grown) == 2, (
        f"ExecutePolicy(+1) must actually launch a second InService instance, got {grown!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
