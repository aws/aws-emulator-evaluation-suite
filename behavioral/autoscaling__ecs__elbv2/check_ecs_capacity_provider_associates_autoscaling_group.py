"""ecs-capacity-provider-associates-autoscaling-group."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "ecs-capacity-provider-associates-autoscaling-group"
GROUP = "resource-binding"
SERVICES = ["autoscaling", "ecs", "elbv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An ECS capacity provider links to its Auto Scaling group both ways: it stores the ASG ARN, ECS
    tags the ASG AmazonECSManaged, and associating the provider shows in the cluster's strategy."""
    ecs = ctx.client("ecs")
    autoscaling = ctx.client("autoscaling")

    _, subnet_ids, _ = _default_vpc_info(ctx)
    ami_id = _al2023_ami_id(ctx)

    lt_name = ctx.unique_name("sim2real-cp-lt-")
    ec2 = ctx.client("ec2")
    lt_id = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": _MANAGED_TAGS}],
    )["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))

    asg_name = ctx.unique_name("sim2real-cp-asg-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
        MinSize=0,
        MaxSize=1,
        DesiredCapacity=0,
        VPCZoneIdentifier=",".join(subnet_ids),
        Tags=[{**t, "PropagateAtLaunch": False} for t in _MANAGED_TAGS],
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_auto_scaling_group(
            AutoScalingGroupName=asg_name, ForceDelete=True
        )
    )
    asg_arn = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ][0]["AutoScalingGroupARN"]

    cp_name = ctx.unique_name("sim2real-capacity-provider-")
    ecs.create_capacity_provider(
        name=cp_name,
        autoScalingGroupProvider={
            "autoScalingGroupArn": asg_arn,
            "managedScaling": {
                "status": "ENABLED",
                "targetCapacity": 100,
                "minimumScalingStepSize": 1,
                "maximumScalingStepSize": 1,
            },
            "managedTerminationProtection": "DISABLED",
        },
        tags=[{"key": t["Key"], "value": t["Value"]} for t in _MANAGED_TAGS],
    )

    def _delete_cp():
        ecs.delete_capacity_provider(capacityProvider=cp_name)

    ctx.on_cleanup(lambda: _retry_while_cluster_busy(_delete_cp))

    described = ecs.describe_capacity_providers(capacityProviders=[cp_name])["capacityProviders"][
        0
    ]
    assert described["autoScalingGroupProvider"]["autoScalingGroupArn"] == asg_arn, (
        f"capacity provider does not reference the ASG ARN it was created with: {described}"
    )
    assert described["status"] == "ACTIVE", f"capacity provider not ACTIVE: {described}"

    # ECS mutates the ASG resource itself: it tags it AmazonECSManaged so that its own
    # service-linked role (whose policy is scoped by that tag) may later manage scaling.
    asg_tags = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ][0]["Tags"]
    tag_keys = {t["Key"] for t in asg_tags}
    assert "AmazonECSManaged" in tag_keys, (
        f"expected ECS to tag the bound ASG AmazonECSManaged, got tags={asg_tags}"
    )

    cluster_name = ctx.unique_name("sim2real-cp-cluster-")
    ecs.create_cluster(
        clusterName=cluster_name,
        tags=[{"key": t["Key"], "value": t["Value"]} for t in _MANAGED_TAGS],
    )
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, cluster_name))

    def _disassociate_cp():
        ecs.put_cluster_capacity_providers(
            cluster=cluster_name, capacityProviders=[], defaultCapacityProviderStrategy=[]
        )

    ctx.on_cleanup(lambda: _retry_while_cluster_busy(_disassociate_cp))

    ecs.put_cluster_capacity_providers(
        cluster=cluster_name,
        capacityProviders=[cp_name],
        defaultCapacityProviderStrategy=[{"capacityProvider": cp_name, "weight": 1, "base": 0}],
    )

    cluster = ecs.describe_clusters(clusters=[cluster_name])["clusters"][0]
    assert cp_name in cluster["capacityProviders"], (
        f"cluster does not list the associated capacity provider: {cluster['capacityProviders']}"
    )
    strategy_providers = {
        s["capacityProvider"] for s in cluster["defaultCapacityProviderStrategy"]
    }
    assert cp_name in strategy_providers, (
        f"cluster default capacity provider strategy missing our provider: {cluster['defaultCapacityProviderStrategy']}"
    )


_MANAGED_TAGS = [{"Key": "sim2real:managed", "Value": "true"}]


def _default_vpc_info(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC in this account/region to place the ASG's subnets")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets")
    subnet_ids = [s["SubnetId"] for s in subnets]
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    sg_id = sgs[0]["GroupId"] if sgs else None
    return vpc_id, subnet_ids, sg_id


def _al2023_ami_id(ctx):
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]


def _drain_and_delete_ecs_cluster(ecs, cluster, timeout_s=900.0, interval_s=10.0):
    """Stop a cluster's services and tasks, wait until the tasks have stopped, then delete it.

    DeleteCluster is refused while services, tasks or container instances remain, and a task's
    ENI stays in the shared network until the task has stopped, which keeps the network from
    being deleted.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s

    def arns(op, key, **kw):
        return [a for page in ecs.get_paginator(op).paginate(cluster=cluster, **kw) for a in page.get(key, [])]

    try:
        services = arns("list_services", "serviceArns")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ClusterNotFoundException":
            return
        raise
    for service in services:
        for call in (
            lambda s=service: ecs.update_service(cluster=cluster, service=s, desiredCount=0),
            lambda s=service: ecs.delete_service(cluster=cluster, service=s, force=True),
        ):
            try:
                call()
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in ("ServiceNotFoundException", "ServiceNotActiveException"):
                    raise
    while True:
        for task in arns("list_tasks", "taskArns", desiredStatus="RUNNING"):
            try:
                ecs.stop_task(cluster=cluster, task=task, reason="sim2real teardown")
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                    raise
        stopping = arns("list_tasks", "taskArns", desiredStatus="STOPPED")
        live = []
        for i in range(0, len(stopping), 100):
            live += [t for t in ecs.describe_tasks(cluster=cluster, tasks=stopping[i:i + 100])["tasks"]
                     if t.get("lastStatus") != "STOPPED"]
        if not live and not arns("list_tasks", "taskArns", desiredStatus="RUNNING"):
            break
        if time.monotonic() >= deadline:
            raise AssertionError(f"{len(live)} task(s) in {cluster} still not STOPPED after {timeout_s:.0f}s")
        time.sleep(interval_s)
    while True:
        try:
            ecs.delete_cluster(cluster=cluster)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ClusterNotFoundException":
                return
            if code == "ClusterContainsContainerInstancesException":
                for instance in arns("list_container_instances", "containerInstanceArns"):
                    try:
                        ecs.deregister_container_instance(cluster=cluster, containerInstance=instance, force=True)
                    except ClientError as exc:
                        if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                            raise
            elif code not in (
                "ClusterContainsTasksException",
                "ClusterContainsServicesException",
                "UpdateInProgressException",
                "ResourceInUseException",
            ):
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _retry_while_cluster_busy(fn, timeout_s=600.0, interval_s=10.0):
    """Run an ECS teardown call, retried while the cluster's capacity-provider attachments still update."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as e:
            if e.response["Error"]["Code"] not in ("UpdateInProgressException", "ResourceInUseException") or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
