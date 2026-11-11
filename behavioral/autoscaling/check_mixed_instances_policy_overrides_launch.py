"""mixed-instances-policy-overrides-launch."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "mixed-instances-policy-overrides-launch"
GROUP = 'group-lifecycle'
SERVICES = ['autoscaling']


def _poll(fn, pred, *, timeout_s, interval_s=5, description="condition"):
    """Poll ``fn`` until ``pred`` holds; raise with the last observed value on timeout."""
    deadline = time.monotonic() + timeout_s
    last = fn()
    while not pred(last):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not met within {timeout_s}s; last={last!r}")
        time.sleep(interval_s)
        last = fn()
    return last


def _error(fn):
    """Run ``fn``, returning the ClientError code it raised. An unexpected SUCCESS raises,
    so a target accepting input AWS refuses is reported as such, not as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A MixedInstancesPolicy round-trips its nested shape (ordered overrides, distribution and
    server-filled defaults), replaces the top-level launch source, and is honoured at launch: the
    instance uses an override type and, with OnDemandBaseCapacity=1, is On-Demand."""
    as_ = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")

    def _image_id():
        param = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
        try:
            return ssm.get_parameter(Name=param)["Parameter"]["Value"]
        except ClientError:
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

    def _make_lt():
        lt_name = ctx.unique_name("sim2real-behav-as-lt-")
        ec2.create_launch_template(
            LaunchTemplateName=lt_name,
            LaunchTemplateData={"ImageId": _image_id(), "InstanceType": "t3.micro"},
            TagSpecifications=[
                {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}
            ],
        )
        ctx.on_cleanup(lambda n=lt_name: ec2.delete_launch_template(LaunchTemplateName=n))
        return lt_name

    def _teardown_asg(name):
        # Billable-leak guard: drain min/max/desired to zero, THEN ForceDelete.
        try:
            as_.update_auto_scaling_group(
                AutoScalingGroupName=name, MinSize=0, MaxSize=0, DesiredCapacity=0
            )
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ValidationError" and "not found" in err.get("Message", ""):
                return
            # A busy group refuses the drain; the ForceDelete below still removes it.
            if err["Code"] not in ("ScalingActivityInProgress", "ResourceContention"):
                raise
        as_.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)

    def _group(name):
        groups = as_.describe_auto_scaling_groups(AutoScalingGroupNames=[name]).get(
            "AutoScalingGroups", []
        )
        return groups[0] if groups else None

    def _in_service(name):
        g = _group(name)
        return sorted(
            i["InstanceId"]
            for i in (g.get("Instances", []) if g else [])
            if i.get("LifecycleState") == "InService"
        )

    lt_name = _make_lt()
    subnets = ",".join(_subnet_ids())
    overrides = [{"InstanceType": "t3.micro"}, {"InstanceType": "t3.small"}]
    policy = {
        "LaunchTemplate": {
            "LaunchTemplateSpecification": {
                "LaunchTemplateName": lt_name,
                "Version": "$Latest",
            },
            "Overrides": overrides,
        },
        "InstancesDistribution": {
            "OnDemandBaseCapacity": 1,
            "OnDemandPercentageAboveBaseCapacity": 100,
            "SpotAllocationStrategy": "lowest-price",
        },
    }

    asg_name = ctx.unique_name("sim2real-behav-as-grp-")
    as_.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        MixedInstancesPolicy=policy,
        MinSize=0,
        MaxSize=1,
        DesiredCapacity=0,
        VPCZoneIdentifier=subnets,
        HealthCheckGracePeriod=0,
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
    )
    ctx.on_cleanup(lambda n=asg_name: _teardown_asg(n))

    group = _group(asg_name)
    assert group is not None, f"the mixed-instances group {asg_name} must be describable"
    got = group.get("MixedInstancesPolicy")
    assert got is not None, (
        f"DescribeAutoScalingGroups must echo the MixedInstancesPolicy, group keys were "
        f"{sorted(group)}"
    )

    spec = got["LaunchTemplate"]["LaunchTemplateSpecification"]
    assert spec["LaunchTemplateName"] == lt_name, spec
    assert spec["Version"] == "$Latest", (
        f"the pinned launch-template version must round-trip literally, got {spec.get('Version')!r}"
    )
    assert [o["InstanceType"] for o in got["LaunchTemplate"]["Overrides"]] == [
        "t3.micro",
        "t3.small",
    ], (
        "the override list must round-trip in the submitted order, got "
        f"{got['LaunchTemplate']['Overrides']}"
    )

    dist = got["InstancesDistribution"]
    assert dist["OnDemandBaseCapacity"] == 1, dist
    assert dist["OnDemandPercentageAboveBaseCapacity"] == 100, dist
    assert dist["SpotAllocationStrategy"] == "lowest-price", dist
    # Server-filled defaults must be materialised, not dropped: an emulator that echoes only the
    # submitted keys leaves the customer unable to read the effective configuration.
    assert dist.get("OnDemandAllocationStrategy") in ("lowest-price", "prioritized"), (
        f"OnDemandAllocationStrategy must be filled with a valid default, got "
        f"{dist.get('OnDemandAllocationStrategy')!r}"
    )
    assert dist.get("SpotInstancePools") == 2, (
        f"SpotInstancePools must default to 2 for the lowest-price strategy, got "
        f"{dist.get('SpotInstancePools')!r}"
    )

    # The mixed-instances policy REPLACES the top-level launch source; both plain launch-source
    # fields must be absent so a reader cannot mistake the group for launch-template-backed.
    assert "LaunchTemplate" not in group, (
        f"a mixed-instances group must not report a top-level LaunchTemplate, got "
        f"{group.get('LaunchTemplate')!r}"
    )
    assert group.get("LaunchConfigurationName") is None, (
        f"a mixed-instances group must not report a LaunchConfigurationName, got "
        f"{group.get('LaunchConfigurationName')!r}"
    )

    # The launch path must honour the policy, not the launch template's own instance type list.
    as_.set_desired_capacity(
        AutoScalingGroupName=asg_name, DesiredCapacity=1, HonorCooldown=False
    )
    live = _poll(
        lambda: _in_service(asg_name),
        lambda ids: len(ids) == 1,
        timeout_s=420,
        interval_s=10,
        description="the mixed-instances group launched one instance to InService",
    )
    described = ec2.describe_instances(InstanceIds=live)["Reservations"][0]["Instances"][0]
    assert described["InstanceType"] in ("t3.micro", "t3.small"), (
        f"the launched instance must use one of the policy overrides, got "
        f"{described['InstanceType']!r}"
    )
    # OnDemandBaseCapacity=1 means the FIRST unit of capacity is On-Demand; EC2 reports
    # InstanceLifecycle only for Spot/Scheduled instances, so it must be absent here.
    assert "InstanceLifecycle" not in described, (
        f"OnDemandBaseCapacity=1 must make the first instance On-Demand, but EC2 reports "
        f"InstanceLifecycle={described.get('InstanceLifecycle')!r}"
    )

    # Rejection half: MixedInstancesPolicy and a top-level LaunchTemplate are mutually exclusive
    # launch sources. Accepting both would leave the group's launch behaviour ambiguous.
    conflicting = ctx.unique_name("sim2real-behav-as-grp-mip-conflict-")
    code, message = _error(
        lambda: as_.create_auto_scaling_group(
            AutoScalingGroupName=conflicting,
            MixedInstancesPolicy=policy,
            LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
            MinSize=0,
            MaxSize=1,
            DesiredCapacity=0,
            VPCZoneIdentifier=subnets,
        )
    )
    assert code == "ValidationError", (
        f"supplying both MixedInstancesPolicy and LaunchTemplate must raise ValidationError, "
        f"got {code!r}"
    )
    expected_message = (
        "Valid requests must contain either LaunchTemplate, LaunchConfigurationName, "
        "InstanceId or MixedInstancesPolicy parameter."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    assert _group(conflicting) is None, (
        f"the rejected group {conflicting} must not have been created"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
