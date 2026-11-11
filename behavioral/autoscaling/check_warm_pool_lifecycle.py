"""warm-pool-lifecycle."""
from __future__ import annotations


from behavioral_harness import tags


CHECK = "warm-pool-lifecycle"
GROUP = 'warm-pool'
SERVICES = ['autoscaling']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutWarmPool creates a describable warm pool config with default PoolState; DeleteWarmPool removes it."""
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

    from botocore.exceptions import ClientError

    name = _make_asg(min_size=0, max_size=2, desired_capacity=0)

    # PutWarmPool depends on the AWSServiceRoleForAutoScaling service-linked role,
    # which AWS auto-creates on first ASG use. On a freshly-created ASG that SLR is
    # briefly "not yet ready for use" (ServiceLinkedRoleFailure). The harness pins
    # botocore max_attempts=1, so retry explicitly until the SLR propagates.
    def _put_warm_pool(**kwargs) -> bool:
        try:
            as_.put_warm_pool(AutoScalingGroupName=name, **kwargs)
            return True
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ServiceLinkedRoleFailure":
                return False
            raise

    # MinSize 0 keeps the pool empty so the config lifecycle is tested without EC2 churn.
    _poll_until(
        lambda: _put_warm_pool(MinSize=0),
        lambda ok: ok,
        timeout_s=120, interval_s=5,
        description="PutWarmPool (waiting for service-linked role)",
    )

    desc = as_.describe_warm_pool(AutoScalingGroupName=name)
    cfg = desc.get("WarmPoolConfiguration")
    assert cfg, "warm pool must be describable after PutWarmPool"
    assert cfg["MinSize"] == 0, f"expected MinSize=0, got {cfg.get('MinSize')!r}"
    assert cfg["PoolState"] == "Stopped", f"default PoolState must be Stopped, got {cfg.get('PoolState')}"

    as_.put_warm_pool(AutoScalingGroupName=name, MinSize=0, PoolState="Running")
    cfg = as_.describe_warm_pool(AutoScalingGroupName=name)["WarmPoolConfiguration"]
    assert cfg["PoolState"] == "Running", "PutWarmPool must update PoolState in place"

    as_.delete_warm_pool(AutoScalingGroupName=name)

    final = _poll_until(
        lambda: as_.describe_warm_pool(AutoScalingGroupName=name),
        lambda d: not d.get("WarmPoolConfiguration"),
        timeout_s=180, interval_s=5,
    )
    assert not final.get("WarmPoolConfiguration"), "deleted warm pool config must disappear"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
