"""op-contract-createCapacityProvider."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-createCapacityProvider"
GROUP = "error-semantics"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCapacityProvider succeeds on a real ASG; min step size > max step size is rejected."""
    ecs = ctx.client("ecs")
    autoscaling = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")

    az = ec2.describe_availability_zones(Filters=[{"Name": "zone-name", "Values": ctx.network().availability_zones}])["AvailabilityZones"][0]["ZoneName"]
    ami_id = _latest_al2023_ami(ec2)
    lt_name = ctx.unique_name("sim2real-behav-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"InstanceType": "t3.micro", "ImageId": ami_id},
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))

    asg_name = ctx.unique_name("sim2real-behav-asg-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=0,
        MaxSize=0,
        DesiredCapacity=0,
        AvailabilityZones=[az],
        NewInstancesProtectedFromScaleIn=True,
        VPCZoneIdentifier=_network_zone_subnets(ctx, [az]),
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)
    )
    asg_arn = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ][0]["AutoScalingGroupARN"]

    cp_name = ctx.unique_name("sim2real-behav-cp-")
    resp = ecs.create_capacity_provider(
        name=cp_name,
        autoScalingGroupProvider={
            "autoScalingGroupArn": asg_arn,
            "managedScaling": {"status": "DISABLED"},
            "managedTerminationProtection": "DISABLED",
        },
    )
    ctx.on_cleanup(lambda: ecs.delete_capacity_provider(capacityProvider=cp_name))
    cp = resp["capacityProvider"]
    assert cp["name"] == cp_name, f"expected capacityProvider.name {cp_name!r}, got {cp['name']!r}"
    assert cp["autoScalingGroupProvider"]["autoScalingGroupArn"] == asg_arn, (
        f"expected autoScalingGroupArn {asg_arn!r}, got {cp['autoScalingGroupProvider']!r}"
    )
    assert cp["status"] == "ACTIVE", f"expected status ACTIVE, got {cp['status']!r}"

    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        described = ecs.describe_capacity_providers(capacityProviders=[cp_name])["capacityProviders"]
        if described and described[0]["status"] == "ACTIVE":
            break
        time.sleep(2)
    else:
        raise AssertionError("capacity provider never reached ACTIVE")

    # Re-creating the same name with a slightly different (but still compatible) config isn't a
    # reliable rejection trigger: CreateCapacityProvider treats a same-named request with a matching
    # ASG as idempotent rather than failing. This check instead exercises the cross-field rule
    # minimumScalingStepSize <= maximumScalingStepSize, which real AWS enforces server-side; a fresh
    # (non-duplicate) name with that relationship inverted reliably trips a rejection. ECS rejects
    # this CreateCapacityProvider parameter validation failure with ClientException.
    invalid_name = ctx.unique_name("sim2real-behav-cp-invalid-")
    err, message = _error(
        lambda: ecs.create_capacity_provider(
            name=invalid_name,
            autoScalingGroupProvider={
                "autoScalingGroupArn": asg_arn,
                "managedScaling": {
                    "status": "ENABLED",
                    "targetCapacity": 80,
                    "minimumScalingStepSize": 10,
                    "maximumScalingStepSize": 1,
                },
                "managedTerminationProtection": "DISABLED",
            },
        )
    )
    assert err == "ClientException", (
        f"expected a rejection (ClientException) for "
        f"minimumScalingStepSize > maximumScalingStepSize, got {err}"
    )
    expected_message = 'The minimum or maximum scaling step size value is invalid. Specify a minimum scaling step size value that is less than or equal to the maximum scaling step size value and try again.'
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the rejected create must not have left a capacity provider behind
    # under the name it was rejected for.
    invalid_created = ecs.describe_capacity_providers(capacityProviders=[invalid_name])[
        "capacityProviders"
    ]
    assert not invalid_created, (
        f"rejected CreateCapacityProvider must not create anything, got {invalid_created}"
    )

    still = ecs.describe_capacity_providers(capacityProviders=[cp_name])["capacityProviders"]
    assert len(still) == 1, f"expected exactly 1 capacity provider named {cp_name!r}, got {still}"
    assert still[0]["autoScalingGroupProvider"]["autoScalingGroupArn"] == asg_arn, (
        f"expected {cp_name!r} still bound to {asg_arn!r}, got {still[0]['autoScalingGroupProvider']!r}"
    )


def _latest_al2023_ami(ec2) -> str:
    """The launch template must carry a valid AMI: CreateAutoScalingGroup rejects a
    launch template without a resolvable ImageId ("You must use a valid fully-formed
    launch template...") before ECS ever sees the ASG."""
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    images.sort(key=lambda i: i["CreationDate"], reverse=True)
    return images[0]["ImageId"]


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises: an
    emulator accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _network_zone_subnets(ctx, zones) -> str:
    """The shared network's subnets in `zones`, comma-separated for VPCZoneIdentifier."""
    by_zone = ctx.network().subnets
    missing = [z for z in zones if z not in by_zone]
    if missing:
        raise AssertionError(f"the run's shared network has no subnet in {missing}")
    return ",".join(by_zone[z] for z in zones)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
