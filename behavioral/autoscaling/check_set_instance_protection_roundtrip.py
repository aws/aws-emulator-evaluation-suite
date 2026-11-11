"""set-instance-protection-roundtrip."""
from __future__ import annotations


from behavioral_harness import tags


CHECK = "set-instance-protection-roundtrip"
GROUP = 'capacity-management'
SERVICES = ['autoscaling']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetInstanceProtection toggles ProtectedFromScaleIn and it is reflected on the instance record."""
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
            TagSpecifications=[{"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
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

    def _wait_for_in_service(name, count, timeout_s=420, interval_s=5):
        def _pred(ins):
            return (
                bool(ins)
                and len(ins) == count
                and all(i.get("LifecycleState") == "InService" for i in ins)
            )
        return _poll_until(lambda: _group_instances(name), _pred, timeout_s, interval_s)

    name = _make_asg(min_size=0, max_size=1, desired_capacity=1)
    # SetInstanceProtection is only legal for InService/Standby instances, so wait
    # for the launch state machine to settle rather than just for the instance to appear.
    instances = _wait_for_in_service(name, 1, timeout_s=420, interval_s=5)
    instance_id = instances[0]["InstanceId"]

    as_.set_instance_protection(
        AutoScalingGroupName=name, InstanceIds=[instance_id], ProtectedFromScaleIn=True
    )
    protected = _poll_until(
        lambda: _group_instances(name),
        lambda ins: any(i["InstanceId"] == instance_id and i["ProtectedFromScaleIn"] is True for i in ins),
        timeout_s=60,
        interval_s=3,
        description=f"instance {instance_id} reflecting ProtectedFromScaleIn=True",
    )
    matched = [i for i in protected if i["InstanceId"] == instance_id]
    assert matched, f"instance {instance_id} missing from group {name} after SetInstanceProtection(True): {protected!r}"
    assert matched[0]["ProtectedFromScaleIn"] is True, (
        f"expected ProtectedFromScaleIn=True for {instance_id}, got {matched[0]['ProtectedFromScaleIn']!r}"
    )

    as_.set_instance_protection(
        AutoScalingGroupName=name, InstanceIds=[instance_id], ProtectedFromScaleIn=False
    )
    unprotected = _poll_until(
        lambda: _group_instances(name),
        lambda ins: any(i["InstanceId"] == instance_id and i["ProtectedFromScaleIn"] is False for i in ins),
        timeout_s=60,
        interval_s=3,
        description=f"instance {instance_id} reflecting ProtectedFromScaleIn=False",
    )
    matched = [i for i in unprotected if i["InstanceId"] == instance_id]
    assert matched, f"instance {instance_id} missing from group {name} after SetInstanceProtection(False): {unprotected!r}"
    assert matched[0]["ProtectedFromScaleIn"] is False, (
        f"expected ProtectedFromScaleIn=False for {instance_id}, got {matched[0]['ProtectedFromScaleIn']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
