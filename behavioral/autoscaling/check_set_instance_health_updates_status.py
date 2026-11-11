"""set-instance-health-updates-status."""
from __future__ import annotations


from behavioral_harness import tags


CHECK = "set-instance-health-updates-status"
GROUP = 'instance-lifecycle'
SERVICES = ['autoscaling']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetInstanceHealth flips HealthStatus to Unhealthy on an InService instance."""
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

    def _instance_lifecycle_state(name, instance_id):
        matched = [i for i in _group_instances(name) if i["InstanceId"] == instance_id]
        return matched[0]["LifecycleState"] if matched else None

    def _make_lt(instance_type="t3.micro"):
        lt_name = ctx.unique_name("sim2real-behav-as-lt-")
        ec2.create_launch_template(
            LaunchTemplateName=lt_name,
            LaunchTemplateData={
                "ImageId": _image_id(),
                "InstanceType": instance_type,
                "TagSpecifications": [
                    {"ResourceType": "instance", "Tags": [{"Key": "sim2real", "Value": CHECK}]},
                    {"ResourceType": "volume", "Tags": [{"Key": "sim2real", "Value": CHECK}]},
                ],
            },
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

    def _wait_for_in_service(name, count, timeout_s=420, interval_s=5):
        def _pred(ins):
            return (
                bool(ins)
                and len(ins) == count
                and all(i.get("LifecycleState") == "InService" for i in ins)
            )
        return _poll_until(lambda: _group_instances(name), _pred, timeout_s, interval_s)

    name = _make_asg(min_size=0, max_size=1, desired_capacity=1)
    instances = _wait_for_in_service(name, 1, timeout_s=420, interval_s=5)
    instance_id = instances[0]["InstanceId"]
    assert instances[0]["HealthStatus"] == "Healthy", (
        f"setup: {instance_id} should start Healthy, got {instances[0]['HealthStatus']!r}"
    )

    # Suspend the remediation processes so the Unhealthy state is observable rather than
    # being immediately consumed by a terminate/replace cycle.
    as_.suspend_processes(
        AutoScalingGroupName=name, ScalingProcesses=["ReplaceUnhealthy", "Terminate", "HealthCheck"]
    )

    as_.set_instance_health(InstanceId=instance_id, HealthStatus="Unhealthy", ShouldRespectGracePeriod=False)

    def get_health():
        matched = [i for i in _group_instances(name) if i["InstanceId"] == instance_id]
        return matched[0]["HealthStatus"] if matched else None

    health = _poll_until(get_health, lambda s: s == "Unhealthy", timeout_s=120, interval_s=3)
    assert health == "Unhealthy", (
        f"SetInstanceHealth must flip {instance_id}'s reported HealthStatus, got {health!r}"
    )
    # With Terminate suspended the unhealthy instance must still be a member of the group.
    lifecycle_state = _instance_lifecycle_state(name, instance_id)
    assert lifecycle_state == "InService", (
        f"with Terminate suspended, an unhealthy instance stays InService, got {lifecycle_state!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
