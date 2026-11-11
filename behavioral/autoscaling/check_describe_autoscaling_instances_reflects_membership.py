"""describe-autoscaling-instances-reflects-membership."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "describe-autoscaling-instances-reflects-membership"
GROUP = "server-side"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAutoScalingInstances aggregates the server-side instance-to-group
    membership: an instance launched by a group's desired capacity shows up tagged
    with that exact AutoScalingGroupName and progresses to LifecycleState=InService."""
    autoscaling = ctx.client("autoscaling")

    ami = _get_al2_ami(ctx)
    subnet_ids = _get_default_subnet_ids(ctx)

    ec2 = ctx.client("ec2")
    lt_name = ctx.unique_name("sim2real-behav-lt-")
    # Deliberately omit InstanceType here: attribute-based instance type selection
    # (below) requires the launch template itself not pin a specific type.
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}
        ],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))

    # Span every default subnet (every AZ) so one capacity-constrained AZ cannot stall the
    # ASG's launch retries, and select instance types by attributes (InstanceRequirements: a
    # micro-class vCPU/memory envelope) rather than a fixed list, so a constrained type has
    # others to fall back to. It still launches exactly one instance from the same launch
    # template/AMI.
    asg_name = ctx.unique_name("sim2real-behav-asg-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        MixedInstancesPolicy={
            "LaunchTemplate": {
                "LaunchTemplateSpecification": {"LaunchTemplateName": lt_name, "Version": "$Latest"},
                "Overrides": [
                    {
                        "InstanceRequirements": {
                            "VCpuCount": {"Min": 1, "Max": 2},
                            "MemoryMiB": {"Min": 512, "Max": 8192},
                            # The AMI resolved above (amzn2-ami-hvm-x86_64-gp2) is x86_64-only.
                            # Attribute-based selection with no CPU manufacturer constraint is
                            # free to pick Graviton (arm64) instance types (e.g. t4g.micro) that
                            # also satisfy the vCPU/memory envelope -- launching those with this
                            # AMI fails architecture compatibility. Restrict to
                            # x86_64-compatible CPU manufacturers so every candidate type in the
                            # pool can actually launch this AMI.
                            "CpuManufacturers": ["intel", "amd"],
                            # The vCPU/memory envelope alone still admits non-burstable families
                            # (e.g. bare-metal, large-memory, or specialty instance types) whose
                            # EC2 boot/initialization time can run well past this check's poll
                            # budget even once launched. This check
                            # only actually needs a plain micro-class burstable instance, so
                            # require BurstablePerformance to pin the pool to the fast-booting
                            # t2/t3/t3a family (the intended "micro-class" equivalent) and exclude
                            # slow-initializing bare-metal/specialty types entirely.
                            "BurstablePerformance": "required",
                        },
                    },
                ],
            },
        },
        MinSize=1,
        MaxSize=1,
        DesiredCapacity=1,
        VPCZoneIdentifier=",".join(subnet_ids),
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)
    )

    # Instance launch + LifecycleState propagation into InService takes one to a few
    # minutes on real AWS (launch, EC2 status checks, ASG marks it Healthy/InService), and
    # capacity-retry backoff can stretch it further. The per-check budget (300 s) wraps the
    # whole run(ctx) but not teardown, so the poll uses nearly all of it, leaving headroom for
    # the setup calls above and the two describe calls after it.
    # NOTE: real AWS's DescribeAutoScalingInstances returns HealthStatus as the
    # upper-cased literal "HEALTHY", not the
    # title-cased "Healthy" the docs' example casing might suggest. Compare
    # case-insensitively so the assertion still requires the instance to be
    # genuinely healthy (not "Unhealthy"/"UNHEALTHY"/etc.) without depending on
    # a specific casing convention that real AWS doesn't actually use.
    instance = _poll_until(
        lambda: _matching_instances(ctx, asg_name),
        lambda instances: (
            len(instances) == 1
            and instances[0]["LifecycleState"] == "InService"
            and instances[0]["HealthStatus"].upper() == "HEALTHY"
        ),
        timeout_s=275.0,
        interval_s=5.0,
    )[0]

    assert instance["AutoScalingGroupName"] == asg_name
    assert instance["LifecycleState"] == "InService"
    assert instance["HealthStatus"].upper() == "HEALTHY"
    assert instance["AvailabilityZone"]
    assert instance["InstanceId"].startswith("i-")

    # A single-instance call filtered by InstanceIds returns the same membership record.
    single = autoscaling.describe_auto_scaling_instances(InstanceIds=[instance["InstanceId"]])
    assert len(single["AutoScalingInstances"]) == 1
    assert single["AutoScalingInstances"][0]["AutoScalingGroupName"] == asg_name


def _get_al2_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    param = ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2")
    return param["Parameter"]["Value"]


def _get_default_subnet_ids(ctx) -> list:

    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    if not subnets:
        raise AssertionError("no default-for-az subnet available in this account/region")
    return [s["SubnetId"] for s in subnets]


def _matching_instances(ctx, asg_name: str) -> list:
    autoscaling = ctx.client("autoscaling")
    pages = autoscaling.get_paginator("describe_auto_scaling_instances").paginate()
    return [
        i for page in pages for i in page["AutoScalingInstances"]
        if i["AutoScalingGroupName"] == asg_name
    ]


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
