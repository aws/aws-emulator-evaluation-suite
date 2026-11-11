"""lifecycle-hook-create-delete-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError


from behavioral_harness import tags


CHECK = "lifecycle-hook-create-delete-lifecycle"
GROUP = 'lifecycle-hooks'
SERVICES = ['autoscaling']


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutLifecycleHook -> DescribeLifecycleHooks(present) -> DeleteLifecycleHook ->
    DescribeLifecycleHooks(absent)."""
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
        }
        params.update(kwargs)
        as_.create_auto_scaling_group(**params)
        ctx.on_cleanup(
            lambda n=asg_name: as_.delete_auto_scaling_group(
                AutoScalingGroupName=n, ForceDelete=True
            )
        )
        return asg_name

    def _error(fn):
        """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
        an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
        try:
            result = fn()
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
        raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED: {result!r}")

    name = _make_asg(min_size=0, max_size=2, desired_capacity=0)
    hook_name = ctx.unique_name("sim2real-behav-hook-")
    as_.put_lifecycle_hook(
        LifecycleHookName=hook_name,
        AutoScalingGroupName=name,
        LifecycleTransition="autoscaling:EC2_INSTANCE_LAUNCHING",
        DefaultResult="ABANDON",
        HeartbeatTimeout=60,
    )
    resp = as_.describe_lifecycle_hooks(AutoScalingGroupName=name, LifecycleHookNames=[hook_name])
    hooks = resp["LifecycleHooks"]
    assert len(hooks) == 1, f"expected exactly one hook named {hook_name!r}, got {hooks!r}"
    assert hooks[0]["LifecycleTransition"] == "autoscaling:EC2_INSTANCE_LAUNCHING", (
        f"expected LifecycleTransition=autoscaling:EC2_INSTANCE_LAUNCHING, got {hooks[0]!r}"
    )
    assert hooks[0]["DefaultResult"] == "ABANDON", (
        f"expected DefaultResult=ABANDON, got {hooks[0]!r}"
    )

    # Overly-permissive guard: an invalid LifecycleTransition value must be rejected.
    bad_hook = ctx.unique_name("sim2real-behav-hook-bad-")
    code, message = _error(
        lambda: as_.put_lifecycle_hook(
            LifecycleHookName=bad_hook,
            AutoScalingGroupName=name,
            LifecycleTransition="autoscaling:NOT_A_REAL_TRANSITION",
        )
    )
    assert code == "ValidationError", f"expected ValidationError for a bad LifecycleTransition, got {code!r}"
    expected = ("'LifecycleTransition' must be one of: autoscaling:EC2_INSTANCE_LAUNCHING, "
                "autoscaling:EC2_INSTANCE_TERMINATING")
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    rejected = as_.describe_lifecycle_hooks(
        AutoScalingGroupName=name, LifecycleHookNames=[bad_hook]
    )["LifecycleHooks"]
    assert rejected == [], (
        f"rejected PutLifecycleHook must not have created {bad_hook!r}, got {rejected!r}"
    )

    as_.delete_lifecycle_hook(LifecycleHookName=hook_name, AutoScalingGroupName=name)
    resp2 = as_.describe_lifecycle_hooks(AutoScalingGroupName=name, LifecycleHookNames=[hook_name])
    assert resp2["LifecycleHooks"] == [], (
        f"deleted hook {hook_name!r} still present in DescribeLifecycleHooks: {resp2['LifecycleHooks']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
