"""set-instance-protection-foreign-instance-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "set-instance-protection-foreign-instance-fails"
GROUP = 'overly-permissive'
SERVICES = ['autoscaling']

_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {description}; last={last!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SetInstanceProtection must reject an instance id that is not a member of the group,
    and must leave a real member's protection flag untouched when it does."""
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
            "Tags": [{"Key": _MANAGED_TAG_KEY, "Value": "true", "PropagateAtLaunch": True}],
        }
        params.update(kwargs)
        as_.create_auto_scaling_group(**params)
        ctx.on_cleanup(
            lambda n=asg_name: as_.delete_auto_scaling_group(
                AutoScalingGroupName=n, ForceDelete=True
            )
        )
        return asg_name

    def _group_instances(asg_name):
        groups = as_.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name]).get(
            "AutoScalingGroups", []
        )
        return groups[0]["Instances"] if groups else []

    def _protection(asg_name, instance_id):
        for inst in _group_instances(asg_name):
            if inst["InstanceId"] == instance_id:
                return inst["ProtectedFromScaleIn"]
        return None

    def _error(fn):
        try:
            fn()
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
        raise AssertionError("expected the call to raise a ClientError, but it succeeded")

    name = _make_asg(min_size=0, max_size=1, desired_capacity=1)
    real_id = _poll_until(
        lambda: _group_instances(name),
        lambda ins: len(ins) == 1 and ins[0]["LifecycleState"] == "InService",
        timeout_s=240,
        interval_s=10,
        description=f"group {name} reaching 1 InService instance",
    )[0]["InstanceId"]

    # Positive control: the real member must be protectable, so a later rejection of the
    # foreign id is known to come from membership, not from a group that rejects every call.
    as_.set_instance_protection(
        AutoScalingGroupName=name, InstanceIds=[real_id], ProtectedFromScaleIn=True
    )
    assert _protection(name, real_id) is True, (
        f"positive control failed: {real_id} should be protected after SetInstanceProtection"
    )

    foreign_id = "i-0123456789abcdef0"
    code, message = _error(
        lambda: as_.set_instance_protection(
            AutoScalingGroupName=name, InstanceIds=[foreign_id], ProtectedFromScaleIn=True
        )
    )
    assert code == "ValidationError", f"expected ValidationError for non-member instance, got {code}"
    expected = f"The instance {foreign_id} is not part of Auto Scaling group {name}."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect-absent: the rejected call must not have touched the real member's protection
    # flag, and the foreign id must not have joined the group as a side effect.
    instances_after = _group_instances(name)
    assert all(i["InstanceId"] != foreign_id for i in instances_after), (
        f"foreign id {foreign_id} must not appear as a member after a rejected call"
    )
    assert _protection(name, real_id) is True, (
        f"the rejected call on {foreign_id} must not change {real_id}'s protection flag"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
