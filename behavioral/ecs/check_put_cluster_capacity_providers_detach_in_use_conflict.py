"""put-cluster-capacity-providers-detach-in-use-conflict."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "put-cluster-capacity-providers-detach-in-use-conflict"
GROUP = 'overly-permissive'
SERVICES = ['ecs']

DEFAULT_CONTAINER_DEFS = [
    {
        "name": "app",
        "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
        "cpu": 64,
        "memory": 128,
        "essential": True,
    }
]


def _poll_until(fn, pred, *, timeout_s=60, interval_s=3, description=""):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = fn()
        if pred(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description!r} (last={last!r})")


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises; success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_shell_capacity_provider(ctx, ecs, *, managed_scaling=None):
    """Create an ASG-backed capacity provider with Min/Max/Desired=0. No real
    EC2 instances ever launch (desired capacity stays 0); this exercises the
    CapacityProvider state machine cheaply.
    """
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    autoscaling = ctx.client("autoscaling")
    ami_id = ssm.get_parameter(
        Name="/aws/service/ecs/optimized-ami/amazon-linux-2023/recommended/image_id"
    )["Parameter"]["Value"]
    az = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}]
    )["AvailabilityZones"][0]["ZoneName"]
    lt_name = ctx.unique_name("sim2real-behav-ecs-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))
    asg_name = ctx.unique_name("sim2real-behav-ecs-asg-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=0,
        MaxSize=0,
        DesiredCapacity=0,
        AvailabilityZones=[az],
        VPCZoneIdentifier=_network_zone_subnets(ctx, [az]),
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)
    )
    asg_arn = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ][0]["AutoScalingGroupARN"]
    cp_name = ctx.unique_name("sim2real-behav-ecs-cp-")
    ecs.create_capacity_provider(
        name=cp_name,
        autoScalingGroupProvider={
            "autoScalingGroupArn": asg_arn,
            "managedScaling": managed_scaling or {"status": "DISABLED"},
            "managedTerminationProtection": "DISABLED",
        },
    )
    ctx.on_cleanup(lambda: ecs.delete_capacity_provider(capacityProvider=cp_name))
    return cp_name


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutClusterCapacityProviders refuses to detach a capacity provider an ACTIVE service still
    uses (ResourceInUseException); the same detach succeeds once the service is gone."""
    ecs = ctx.client("ecs")
    # CreateCapacityProvider requires the ECS service-linked role to exist.
    try:
        ctx.client("iam").create_service_linked_role(AWSServiceName="ecs.amazonaws.com")
    except Exception:  # noqa: BLE001 — already-exists (InvalidInput) is success
        pass
    cp_name = _create_shell_capacity_provider(ctx, ecs)
    name = ctx.unique_name("sim2real-behav-ecs-cluster-")
    ecs.create_cluster(clusterName=name)
    ctx.on_cleanup(lambda: _retry_while_updating(lambda: ecs.delete_cluster(cluster=name)))
    family = ctx.unique_name("sim2real-behav-ecs-taskdef-")
    td = ecs.register_task_definition(family=family, containerDefinitions=DEFAULT_CONTAINER_DEFS)[
        "taskDefinition"
    ]
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[td["taskDefinitionArn"]]))
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=td["taskDefinitionArn"]))

    ecs.put_cluster_capacity_providers(
        cluster=name,
        capacityProviders=[cp_name],
        defaultCapacityProviderStrategy=[{"capacityProvider": cp_name, "weight": 1}],
    )
    ctx.on_cleanup(
        lambda: _retry_while_updating(
            lambda: ecs.put_cluster_capacity_providers(
                cluster=name, capacityProviders=[], defaultCapacityProviderStrategy=[]
            )
        )
    )
    _poll_until(
        lambda: ecs.describe_clusters(clusters=[name])["clusters"][0],
        lambda c: cp_name in c.get("capacityProviders", []),
        timeout_s=60,
        interval_s=3,
        description="the capacity provider becomes attached to the cluster",
    )

    svc_name = ctx.unique_name("sim2real-behav-ecs-svc-")
    ecs.create_service(
        cluster=name,
        serviceName=svc_name,
        taskDefinition=td["taskDefinitionArn"],
        desiredCount=0,
        capacityProviderStrategy=[{"capacityProvider": cp_name, "weight": 1}],
    )
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=name, service=svc_name, force=True))

    # The attach applies asynchronously; a detach returns UpdateInProgressException until it
    # settles, so poll until the in-use conflict is evaluated.
    code, message = _poll_until(
        lambda: _error(
            lambda: ecs.put_cluster_capacity_providers(
                cluster=name, capacityProviders=[], defaultCapacityProviderStrategy=[]
            )
        ),
        lambda err: err[0] != "UpdateInProgressException",
        timeout_s=120,
        interval_s=5,
        description="the cluster capacity-provider association settles so the detach is evaluated",
    )
    assert code == "ResourceInUseException", (
        f"expected ResourceInUseException detaching a capacity provider still used by an ACTIVE "
        f"service, got {code}"
    )
    assert message == "The specified capacity provider is in use and cannot be removed.", message
    still_attached = ecs.describe_clusters(clusters=[name])["clusters"][0]
    assert cp_name in still_attached.get("capacityProviders", []), (
        "a rejected detach attempt must not have removed the capacity provider from the cluster"
    )

    ecs.delete_service(cluster=name, service=svc_name, force=True)
    _poll_until(
        lambda: ecs.describe_services(cluster=name, services=[svc_name])["services"][0],
        lambda s: s["status"] == "INACTIVE",
        timeout_s=90,
        interval_s=3,
        description="the service reaches INACTIVE after forced delete, freeing the capacity provider",
    )

    # restore: the identical detach call, now that the dependent service is gone, must succeed.
    def _detach_outcome():
        try:
            ecs.put_cluster_capacity_providers(
                cluster=name, capacityProviders=[], defaultCapacityProviderStrategy=[]
            )
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")
        return "accepted"

    restore_outcome = _poll_until(
        _detach_outcome,
        lambda outcome: outcome == "accepted",
        timeout_s=60,
        interval_s=5,
        description="the identical detach call succeeds now that the dependent service is gone",
    )
    assert restore_outcome == "accepted", (
        f"expected the detach to succeed once the dependent service was gone, got {restore_outcome}"
    )
    detached = ecs.describe_clusters(clusters=[name])["clusters"][0]
    assert detached.get("capacityProviders", []) == [], (
        f"expected the capacity provider to be detached from the cluster once the dependent "
        f"service was gone, still present: {detached.get('capacityProviders')}"
    )


def _retry_while_updating(fn, timeout_s=180.0, interval_s=5.0):
    """Call fn() until the cluster's capacity-provider attachment settles: ECS refuses cluster
    updates and deletes with UpdateInProgressException until then."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "UpdateInProgressException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


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
