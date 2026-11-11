"""delete-cluster-with-active-capacity-providers-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "delete-cluster-with-active-capacity-providers-rejected"
GROUP = "concurrency"
SERVICES = ["ecs"]

_ECS_TAGS = [{"key": "sim2real", "value": "true"}]
_EC2_TAGS = [{"Key": "sim2real:managed", "Value": "true"}]


@tags("axis:happy-path", "cap:c1", "cap:c4", "plane:control")
def run(ctx) -> None:
    """DeleteCluster on a cluster whose only capacity provider is backed by an Auto Scaling group
    leaves the cluster INACTIVE, while the provider, which belongs to the account, stays ACTIVE
    on its group."""
    ecs = ctx.client("ecs")
    ec2 = ctx.client("ec2")
    autoscaling = ctx.client("autoscaling")

    net = ctx.network()
    ami_id = _find_ami(ec2)

    lt_name = ctx.unique_name("sim2real-behav-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": _EC2_TAGS}],
    )
    ctx.on_cleanup(lambda: _safe_delete_launch_template(ec2, lt_name))

    asg_name = ctx.unique_name("sim2real-behav-asg-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=0,
        MaxSize=0,
        DesiredCapacity=0,
        VPCZoneIdentifier=net.subnet_ids[0],
        NewInstancesProtectedFromScaleIn=True,
        Tags=[{"Key": "sim2real:managed", "Value": "true", "PropagateAtLaunch": False}],
    )
    ctx.on_cleanup(lambda: _safe_delete_asg(autoscaling, asg_name))

    asg_arn = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ][0]["AutoScalingGroupARN"]

    cp_name = ctx.unique_name("sim2real-behav-cp-")
    ecs.create_capacity_provider(
        name=cp_name,
        autoScalingGroupProvider={
            "autoScalingGroupArn": asg_arn,
            "managedScaling": {"status": "ENABLED", "targetCapacity": 100},
            "managedTerminationProtection": "ENABLED",
        },
        tags=_ECS_TAGS,
    )
    ctx.on_cleanup(lambda: _safe_delete_capacity_provider(ecs, cp_name))

    def _cp_status():
        resp = ecs.describe_capacity_providers(capacityProviders=[cp_name])
        cps = resp.get("capacityProviders", [])
        return cps[0]["status"] if cps else None

    _poll_until(_cp_status, lambda s: s == "ACTIVE", timeout_s=60.0, interval_s=3.0)

    cluster_name = ctx.unique_name("sim2real-behav-cl-")
    cluster_arn = ecs.create_cluster(clusterName=cluster_name, tags=_ECS_TAGS)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _safe_delete_cluster(ctx, cluster_arn))

    ecs.put_cluster_capacity_providers(
        cluster=cluster_arn,
        capacityProviders=[cp_name],
        defaultCapacityProviderStrategy=[{"capacityProvider": cp_name, "weight": 1, "base": 0}],
    )

    # PutClusterCapacityProviders is asynchronous: the cluster's `capacityProviders`
    # list is updated immediately, but the association-update itself keeps running
    # in the background (tracked via `attachmentsStatus`). If DeleteCluster races
    # that in-flight update it returns UpdateInProgressException rather than the
    # ClusterContainsCapacityProviderException we actually want to exercise here,
    # so wait for the update to fully settle (attachmentsStatus no longer
    # UPDATE_IN_PROGRESS) before deleting.
    def _settled():
        cluster = ecs.describe_clusters(clusters=[cluster_arn], include=["ATTACHMENTS"])["clusters"][0]
        if cp_name not in cluster.get("capacityProviders", []):
            return None
        if cluster.get("attachmentsStatus") == "UPDATE_COMPLETE":
            return cluster
        return None

    _poll_until(_settled, lambda c: c is not None, timeout_s=90.0, interval_s=3.0)

    def _attempt_delete():
        try:
            ecs.delete_cluster(cluster=cluster_arn)
            return ("SUCCESS", "")
        except Exception as exc:  # noqa: BLE001
            err_code = _error_code_from_exc(exc)
            err_message = ""
            resp = getattr(exc, "response", None)
            if isinstance(resp, dict):
                err_message = resp.get("Error", {}).get("Message", "")
            return (err_code, err_message)

    # A DeleteCluster that races the settling association update returns
    # UpdateInProgressException; retry (bounded) until it gets past that transient state.
    code, message = _poll_until(
        _attempt_delete,
        lambda result: result[0] != "UpdateInProgressException",
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert code == "SUCCESS", f"expected DeleteCluster to succeed, got code={code!r} message={message!r}"

    deleted = _poll_until(
        lambda: ecs.describe_clusters(clusters=[cluster_arn])["clusters"][0]["status"],
        lambda st: st == "INACTIVE",
        timeout_s=120.0,
        interval_s=3.0,
    )
    assert deleted == "INACTIVE", deleted

    cp = ecs.describe_capacity_providers(capacityProviders=[cp_name])["capacityProviders"]
    assert len(cp) == 1 and cp[0]["status"] == "ACTIVE", f"capacity provider after cluster delete: {cp!r}"
    assert cp[0]["autoScalingGroupProvider"]["autoScalingGroupArn"] == asg_arn, cp[0]


def _error_code_from_exc(exc: Exception) -> str:
    resp = getattr(exc, "response", None)
    if isinstance(resp, dict):
        return resp.get("Error", {}).get("Code", type(exc).__name__)
    return type(exc).__name__


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last}")


def _retry_delete(delete, *, timeout_s: float, gone_codes=()) -> None:
    """Teardown: retry a delete within ``timeout_s``; a code in ``gone_codes`` means already gone.
    The last error is raised so a leak is reported, never swallowed."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete()
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in gone_codes:
                return
            if time.monotonic() >= deadline:
                raise
        time.sleep(3.0)


def _safe_delete_cluster(ctx, cluster_arn: str) -> None:
    ecs = ctx.client("ecs")
    clusters = ecs.describe_clusters(clusters=[cluster_arn])["clusters"]
    if not clusters or clusters[0]["status"] == "INACTIVE":
        return
    ecs.put_cluster_capacity_providers(
        cluster=cluster_arn, capacityProviders=[], defaultCapacityProviderStrategy=[]
    )
    _retry_delete(
        lambda: ecs.delete_cluster(cluster=cluster_arn),
        timeout_s=60.0,
        gone_codes=("ClusterNotFoundException",),
    )


def _find_ami(ec2) -> str:
    resp = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["amzn2-ami-hvm-*-x86_64-gp2"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )
    images = resp.get("Images", [])
    if not images:
        raise AssertionError("no Amazon Linux 2 AMI available to back a capacity-provider Auto Scaling group")
    images.sort(key=lambda i: i.get("CreationDate", ""), reverse=True)
    return images[0]["ImageId"]


def _safe_delete_launch_template(ec2, lt_name: str) -> None:
    _retry_delete(
        lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name),
        timeout_s=60.0,
        gone_codes=("InvalidLaunchTemplateName.NotFoundException",),
    )


def _safe_delete_asg(autoscaling, asg_name: str) -> None:
    """Teardown: delete the group, then wait until it is gone so its launch template can go."""
    _retry_delete(
        lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True),
        timeout_s=120.0,
    )
    _poll_until(
        lambda: autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"],
        lambda groups: not groups,
        timeout_s=600.0,
        interval_s=10.0,
    )


def _safe_delete_capacity_provider(ecs, cp_name: str) -> None:
    """Teardown: DeleteCapacityProvider moves it to DELETE_IN_PROGRESS; wait until it leaves."""
    _retry_delete(lambda: ecs.delete_capacity_provider(capacityProvider=cp_name), timeout_s=90.0)
    _poll_until(
        lambda: [
            c["status"]
            for c in ecs.describe_capacity_providers(capacityProviders=[cp_name])["capacityProviders"]
            if c["status"] != "INACTIVE"
        ],
        lambda live: not live,
        timeout_s=600.0,
        interval_s=10.0,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
