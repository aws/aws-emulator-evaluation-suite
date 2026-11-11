"""capacity-provider-managed-scaling-enforced."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "capacity-provider-managed-scaling-enforced"
GROUP = 'capacity-provider'
SERVICES = ['ecs']

# Tagged so a capacity provider, ASG or launch template left behind by a failed cleanup
# remains discoverable.
_MANAGED_TAG_KV = ("sim2real:managed", "true")
_ECS_TAGS = [{"key": _MANAGED_TAG_KV[0], "value": _MANAGED_TAG_KV[1]}]
_EC2_TAGS = [{"Key": _MANAGED_TAG_KV[0], "Value": _MANAGED_TAG_KV[1]}]


def _poll_until(fn, pred, *, timeout_s=60, interval_s=3, description=""):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = fn()
        if pred(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description!r} (last={last!r})")


def _put_cluster_capacity_providers_retrying(ecs, *, cluster, capacity_providers, strategy, timeout_s=45, interval_s=3):
    """Retry PutClusterCapacityProviders on UpdateInProgressException (cluster busy while a prior
    association settles; no describable field exposes that state). Bounded; other errors raise."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ecs.put_cluster_capacity_providers(
                cluster=cluster,
                capacityProviders=capacity_providers,
                defaultCapacityProviderStrategy=strategy,
            )
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "UpdateInProgressException":
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"cluster {cluster!r} still busy after {timeout_s}s: {exc}"
                ) from exc
            time.sleep(interval_s)


def _delete_cluster_retrying(ecs, cluster, timeout_s=90, interval_s=5):
    """DeleteCluster answers UpdateInProgressException while the capacity-provider
    disassociation is still settling; retry on that code only, bounded."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ecs.delete_cluster(cluster=cluster)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "UpdateInProgressException":
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises:
    accepting input that AWS refuses must not be reported as a mere error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_unused_asg(ctx):
    """A fresh zero-capacity ASG. An ASG can back only one capacity provider, so reusing one
    could be rejected for the association rather than for the input under test."""
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    autoscaling = ctx.client("autoscaling")
    ami_id = ssm.get_parameter(
        Name="/aws/service/ecs/optimized-ami/amazon-linux-2023/recommended/image_id"
    )["Parameter"]["Value"]
    # Pin the ASG to an explicit subnet of the run's shared network (a bare AvailabilityZones
    # list resolves to the AZ's default subnet). The group is MinSize/MaxSize/Desired=0, so it
    # never launches an instance and one subnet will do.
    subnet_id = ctx.network().subnet_ids[0]
    lt_name = ctx.unique_name("sim2real-behav-ecs-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": _EC2_TAGS}],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))
    asg_name = ctx.unique_name("sim2real-behav-ecs-asg-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=0,
        MaxSize=0,
        DesiredCapacity=0,
        VPCZoneIdentifier=subnet_id,
        Tags=_EC2_TAGS,
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)
    )
    return autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ][0]["AutoScalingGroupARN"]


def _create_shell_capacity_provider(ctx, ecs, *, managed_scaling=None):
    asg_arn = _create_unused_asg(ctx)
    cp_name = ctx.unique_name("sim2real-behav-ecs-cp-")
    ecs.create_capacity_provider(
        name=cp_name,
        autoScalingGroupProvider={
            "autoScalingGroupArn": asg_arn,
            "managedScaling": managed_scaling or {"status": "DISABLED"},
            "managedTerminationProtection": "DISABLED",
        },
        tags=_ECS_TAGS,
    )
    ctx.on_cleanup(lambda: ecs.delete_capacity_provider(capacityProvider=cp_name))
    return cp_name


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """managedScaling settings (status, targetCapacity, min/maximumScalingStepSize) read back as
    configured, also after cluster association; targetCapacity 150 (outside 1-100) is rejected
    with ClientException and creates nothing."""
    ecs = ctx.client("ecs")
    # CreateCapacityProvider requires the ECS service-linked role to exist.
    try:
        ctx.client("iam").create_service_linked_role(AWSServiceName="ecs.amazonaws.com")
    except Exception:  # noqa: BLE001 — already-exists (InvalidInput) is success
        pass
    name = ctx.unique_name("sim2real-behav-ecs-cluster-")
    ecs.create_cluster(clusterName=name, tags=_ECS_TAGS)
    ctx.on_cleanup(lambda: _delete_cluster_retrying(ecs, name))

    cp_name = _create_shell_capacity_provider(
        ctx,
        ecs,
        managed_scaling={
            "status": "ENABLED",
            "targetCapacity": 75,
            "minimumScalingStepSize": 1,
            "maximumScalingStepSize": 10,
        },
    )

    # DescribeCapacityProviders is eventually consistent right after create; poll until present.
    described = _poll_until(
        lambda: ecs.describe_capacity_providers(capacityProviders=[cp_name])["capacityProviders"],
        lambda cps: bool(cps),
        timeout_s=30,
        interval_s=3,
        description="the just-created capacity provider becomes describable",
    )[0]
    scaling = described.get("autoScalingGroupProvider", {}).get("managedScaling", {})
    assert scaling.get("status") == "ENABLED", scaling
    assert scaling.get("targetCapacity") == 75, scaling
    assert scaling.get("minimumScalingStepSize") == 1, scaling
    assert scaling.get("maximumScalingStepSize") == 10, scaling

    # Registered last so it runs first (LIFO): ECS refuses to delete a capacity provider still
    # associated with a cluster. The disassociate retries on the cluster's transient busy state.
    def _disassociate_and_wait():
        _put_cluster_capacity_providers_retrying(
            ecs, cluster=name, capacity_providers=[], strategy=[]
        )
        _poll_until(
            lambda: ecs.describe_clusters(clusters=[name])["clusters"][0],
            lambda c: cp_name not in c.get("capacityProviders", []),
            timeout_s=30,
            interval_s=3,
            description="capacity provider disassociated from the cluster before deleting it",
        )

    ctx.on_cleanup(_disassociate_and_wait)
    _put_cluster_capacity_providers_retrying(
        ecs,
        cluster=name,
        capacity_providers=[cp_name],
        strategy=[{"capacityProvider": cp_name, "weight": 1}],
    )
    described_after_assoc = _poll_until(
        lambda: ecs.describe_capacity_providers(capacityProviders=[cp_name])["capacityProviders"][0],
        lambda cp: cp.get("autoScalingGroupProvider", {}).get("managedScaling", {}).get("targetCapacity")
        == 75,
        timeout_s=30,
        interval_s=3,
        description="managedScaling settings remain unchanged after cluster association",
    )
    scaling_after = described_after_assoc.get("autoScalingGroupProvider", {}).get("managedScaling", {})
    assert scaling_after.get("targetCapacity") == 75, scaling_after
    described_cluster = ecs.describe_clusters(clusters=[name])["clusters"][0]
    assert cp_name in described_cluster.get("capacityProviders", []), described_cluster

    # targetCapacity outside [1, 100] is rejected and creates no capacity provider.
    bogus_name = ctx.unique_name("sim2real-behav-ecs-cp-bad-")
    code, message = _error(
        lambda: ecs.create_capacity_provider(
            name=bogus_name,
            autoScalingGroupProvider={
                # A fresh ASG, so the rejection is for targetCapacity, not an already-used ASG.
                "autoScalingGroupArn": _create_unused_asg(ctx),
                "managedScaling": {"status": "ENABLED", "targetCapacity": 150},
            },
        )
    )
    assert code == "ClientException", (
        f"expected a rejection for targetCapacity=150 (outside the documented 1-100 range), got {code}"
    )
    assert message == (
        "The managed scaling target capacity value is invalid. Specify an integer greater than 0 "
        "and less than or equal to 100 and try again."
    ), f"targetCapacity=150: unexpected message {message!r}"
    still_absent = ecs.describe_capacity_providers(capacityProviders=[bogus_name])["capacityProviders"]
    assert not still_absent, (
        f"a rejected out-of-range CreateCapacityProvider must not create anything: {still_absent}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
