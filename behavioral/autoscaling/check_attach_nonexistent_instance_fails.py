"""attach-nonexistent-instance-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "attach-nonexistent-instance-fails"
GROUP = 'overly-permissive'
SERVICES = ['autoscaling']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AttachInstances rejects a nonexistent instance id with an exact ValidationError, while the
    same call with a real instance succeeds, so the refusal is specific to the bad id."""
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
        )
        ctx.on_cleanup(lambda n=lt_name: ec2.delete_launch_template(LaunchTemplateName=n))
        return lt_name

    def _make_asg(
        min_size=0, max_size=1, desired_capacity=0, launch_template_name=None,
        register_cleanup=True, **kwargs,
    ):
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
        if register_cleanup:
            ctx.on_cleanup(
                lambda n=asg_name: as_.delete_auto_scaling_group(
                    AutoScalingGroupName=n, ForceDelete=True
                )
            )
        return asg_name

    def _poll_until(probe, predicate, timeout_s=90.0, interval_s=5.0):
        deadline = time.monotonic() + timeout_s
        last = None
        while time.monotonic() < deadline:
            last = probe()
            if predicate(last):
                return last
            time.sleep(interval_s)
        raise AssertionError(f"condition not met within {timeout_s}s, last value: {last!r}")

    # Group cleanup is registered after the instance's, so ForceDelete runs first on teardown;
    # terminating an attached instance under a live group would launch a replacement.
    name = _make_asg(min_size=0, max_size=2, desired_capacity=0, register_cleanup=False)

    code, message = _client_error(
        lambda: as_.attach_instances(
            AutoScalingGroupName=name, InstanceIds=["i-0123456789abcdef0"]
        )
    )
    assert code == "ValidationError", f"expected ValidationError, got {code}"
    assert message == "Instance [i-0123456789abcdef0] is invalid.", f"expected the exact refusal message, got {message!r}"

    assert _group_instances(name) == [], "failed attach must not add a phantom instance"

    # Positive control: the same call with a real instance in the group's subnets succeeds.
    subnet_id = _subnet_ids()[0]
    marker = ctx.unique_name("sim2real-behav-as-instance-")
    run_resp = ec2.run_instances(
        ImageId=_image_id(),
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_id,
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": marker}]}
        ],
    )
    instance_id = run_resp["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda i=instance_id: ec2.terminate_instances(InstanceIds=[i]))
    ctx.on_cleanup(
        lambda n=name: as_.delete_auto_scaling_group(AutoScalingGroupName=n, ForceDelete=True)
    )
    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    as_.attach_instances(AutoScalingGroupName=name, InstanceIds=[instance_id])
    attached = _poll_until(
        lambda: _group_instances(name),
        lambda instances: any(i["InstanceId"] == instance_id for i in instances),
    )
    assert any(i["InstanceId"] == instance_id for i in attached), (
        f"real instance {instance_id} was not attached after a valid AttachInstances call, "
        f"got {attached!r}"
    )


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
