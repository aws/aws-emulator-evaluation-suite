"""capacity-provider-lifecycle-active-to-inactive."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "capacity-provider-lifecycle-active-to-inactive"
GROUP = "cross-service"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCapacityProvider backed by a real (zero-capacity) Auto Scaling group
    reaches ACTIVE, and DeleteCapacityProvider drives it to INACTIVE."""
    ecs = ctx.client("ecs")
    autoscaling = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")

    try:
        ami_id = ssm.get_parameter(
            Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
        )["Parameter"]["Value"]
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(f"could not resolve a default AMI via SSM: {exc}") from exc

    net = _default_network(ctx)

    lt_name = ctx.unique_name("sim2real-ecs-lt-")
    try:
        lt = ec2.create_launch_template(
            LaunchTemplateName=lt_name,
            LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
            TagSpecifications=[
                {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": "true"}]}
            ],
        )["LaunchTemplate"]
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(f"cannot create launch template in this environment: {exc}") from exc
    ctx.on_cleanup(
        lambda: ec2.delete_launch_template(LaunchTemplateId=lt["LaunchTemplateId"])
    )

    asg_name = ctx.unique_name("sim2real-ecs-asg-")
    try:
        autoscaling.create_auto_scaling_group(
            AutoScalingGroupName=asg_name,
            LaunchTemplate={"LaunchTemplateId": lt["LaunchTemplateId"], "Version": "$Latest"},
            MinSize=0,
            MaxSize=0,
            DesiredCapacity=0,
            VPCZoneIdentifier=",".join(net["subnets"]),
            NewInstancesProtectedFromScaleIn=True,
            Tags=[{"Key": "sim2real", "Value": "true", "PropagateAtLaunch": False}],
        )
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(f"cannot create an Auto Scaling group in this environment: {exc}") from exc
    ctx.on_cleanup(
        lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)
    )

    asg = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ][0]
    asg_arn = asg["AutoScalingGroupARN"]
    assert asg["DesiredCapacity"] == 0, "the ASG must stay at zero capacity to avoid launching real instances"

    cp_name = ctx.unique_name("sim2real-ecs-cp-")
    created = ecs.create_capacity_provider(
        name=cp_name,
        autoScalingGroupProvider={
            "autoScalingGroupArn": asg_arn,
            "managedScaling": {
                "status": "DISABLED",
                "targetCapacity": 100,
            },
            "managedTerminationProtection": "DISABLED",
        },
        tags=[{"key": "sim2real", "value": "true"}],
    )["capacityProvider"]
    ctx.on_cleanup(lambda: ecs.delete_capacity_provider(capacityProvider=cp_name))
    assert created["name"] == cp_name, f"CreateCapacityProvider echoed name {created['name']!r}, expected {cp_name!r}"

    def _describe():
        resp = ecs.describe_capacity_providers(capacityProviders=[cp_name])
        return resp["capacityProviders"][0] if resp["capacityProviders"] else None

    active = _poll_until(_describe, lambda cp: cp is not None and cp["status"] == "ACTIVE", timeout_s=120.0)
    assert active["status"] == "ACTIVE", f"expected ACTIVE after create, got {active['status']!r}"

    ecs.delete_capacity_provider(capacityProvider=cp_name)

    def _terminal():
        cp = _describe()
        return "INACTIVE" if cp is None else cp["status"]

    final_status = _poll_until(_terminal, lambda s: s in ("INACTIVE",), timeout_s=180.0)
    assert final_status == "INACTIVE", f"expected INACTIVE after delete, got {final_status!r}"


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last state={last!r}")


def _default_network(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]).get("Subnets", [])
    if not subnets:
        raise AssertionError("no subnets available in VPC")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    ).get("SecurityGroups", [])
    return {
        "subnets": [s["SubnetId"] for s in subnets[:2]],
        "security_groups": [sgs[0]["GroupId"]] if sgs else [],
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
