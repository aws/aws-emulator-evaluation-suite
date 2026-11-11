"""instance-protection-blocks-scale-in."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "instance-protection-blocks-scale-in"
GROUP = 'instance-lifecycle'
SERVICES = ['autoscaling']


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A ProtectedFromScaleIn instance must survive a scale-in that terminates its unprotected sibling."""
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

    def _instance_state(name, instance_id):
        for inst in _group_instances(name):
            if inst["InstanceId"] == instance_id:
                return inst["LifecycleState"]
        return None

    def _ec2_state(instance_id):
        for res in ec2.describe_instances(InstanceIds=[instance_id]).get("Reservations", []):
            for inst in res.get("Instances", []):
                if inst["InstanceId"] == instance_id:
                    return inst["State"]["Name"]
        raise AssertionError(f"instance {instance_id!r} not found in DescribeInstances")

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

        def _teardown(n=asg_name):
            # Draining first means ForceDelete is not racing the group's own attempt to
            # relaunch capacity, so no EC2 instance is left behind for the launch template
            # cleanup (registered before this, LIFO-after) to be blocked on.
            try:
                as_.update_auto_scaling_group(
                    AutoScalingGroupName=n, MinSize=0, MaxSize=0, DesiredCapacity=0
                )
            except ClientError as exc:
                err = exc.response["Error"]
                if err["Code"] == "ValidationError" and "not found" in err.get("Message", ""):
                    return
                # A busy group refuses the drain; the ForceDelete below still removes it.
                if err["Code"] not in ("ScalingActivityInProgress", "ResourceContention"):
                    raise
            as_.delete_auto_scaling_group(AutoScalingGroupName=n, ForceDelete=True)

        ctx.on_cleanup(_teardown)
        return asg_name

    def _wait_for_in_service(name, count, timeout_s=420, interval_s=5):
        def _pred(ins):
            return (
                bool(ins)
                and len(ins) == count
                and all(i.get("LifecycleState") == "InService" for i in ins)
            )
        return _poll_until(lambda: _group_instances(name), _pred, timeout_s, interval_s)

    name = _make_asg(min_size=0, max_size=2, desired_capacity=2)
    instances = _wait_for_in_service(name, 2, timeout_s=420, interval_s=5)
    ids = [i["InstanceId"] for i in instances]
    protected_id, other_id = ids[0], ids[1]

    as_.set_instance_protection(
        AutoScalingGroupName=name,
        InstanceIds=[protected_id],
        ProtectedFromScaleIn=True,
    )
    flags = {i["InstanceId"]: i["ProtectedFromScaleIn"] for i in _group_instances(name)}
    assert flags[protected_id] is True, flags
    assert flags[other_id] is False, flags

    as_.set_desired_capacity(AutoScalingGroupName=name, DesiredCapacity=1)
    _poll_until(
        lambda: _instance_state(name, other_id),
        lambda s: s != "InService",
        timeout_s=180,
        interval_s=5,
        description=f"unprotected instance {other_id} leaving InService",
    )
    assert _instance_state(name, protected_id) == "InService", (
        "the protected instance must be the survivor of scale-in"
    )

    # ASG's own bookkeeping is not enough: a target could flip LifecycleState without ever
    # asking EC2 to terminate anything. Confirm the real side effect at EC2 directly, at the
    # destination the ASG's TerminateInstanceInAutoScalingGroup call is supposed to reach.
    ec2_other_state = _poll_until(
        lambda: _ec2_state(other_id),
        lambda s: s in ("shutting-down", "terminated"),
        timeout_s=180,
        interval_s=5,
        description=f"unprotected instance {other_id} actually terminated at EC2",
    )
    assert ec2_other_state in ("shutting-down", "terminated"), (
        f"unprotected instance {other_id} was not really terminated at EC2: {ec2_other_state!r}"
    )
    ec2_protected_state = _ec2_state(protected_id)
    assert ec2_protected_state == "running", (
        f"protected instance {protected_id} is not running at EC2: {ec2_protected_state!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
