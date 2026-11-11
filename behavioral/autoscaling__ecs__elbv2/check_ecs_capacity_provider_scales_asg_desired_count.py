"""ecs-capacity-provider-scales-asg-desired-count."""
from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ecs-capacity-provider-scales-asg-desired-count"
GROUP = "resource-binding"
SERVICES = ["autoscaling", "ecs", "elbv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:e2e", "plane:control")
def run(ctx) -> None:
    """ECS managed scaling raises the desired capacity of a capacity provider's 0-capacity ASG
    when a service with a capacity-provider strategy has a task it cannot place. A service is used
    because RunTask is rejected outright when the capacity provider has no container instances."""
    iam = ctx.client("iam")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    autoscaling = ctx.client("autoscaling")
    ecs = ctx.client("ecs")

    _, subnet_ids, _ = _default_vpc_info(ctx)
    ami_id = _ecs_optimized_ami_id(ssm)

    # --- IAM role + instance profile so EC2 instances can register with the cluster ---
    role_name = ctx.unique_name("sim2real-cp-scale-instrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role",
    )
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role",
        )
    )
    profile_name = ctx.unique_name("sim2real-cp-scale-instprofile-")
    iam.create_instance_profile(
        InstanceProfileName=profile_name, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    ctx.on_cleanup(
        lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=profile_name, RoleName=role_name
        )
    )
    _poll_until(
        lambda: iam.get_instance_profile(InstanceProfileName=profile_name),
        lambda r: bool(r["InstanceProfile"]["Roles"]),
        timeout_s=30.0,
        interval_s=2.0,
    )

    cluster_name = ctx.unique_name("sim2real-cp-scale-cluster-")

    # --- launch template + ASG (starts empty: desired capacity 0) ---
    user_data = f"#!/bin/bash\necho ECS_CLUSTER={cluster_name} >> /etc/ecs/ecs.config\n"
    lt_name = ctx.unique_name("sim2real-cp-scale-lt-")
    lt_id = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={
            "ImageId": ami_id,
            "InstanceType": "t3.micro",
            "IamInstanceProfile": {"Name": profile_name},
            "UserData": base64.b64encode(user_data.encode()).decode(),
            "TagSpecifications": [
                {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": lt_name}]}
            ],
        },
        TagSpecifications=[
            {
                "ResourceType": "launch-template",
                "Tags": [{"Key": "sim2real", "Value": CHECK}],
            }
        ],
    )["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))

    ecs.create_cluster(clusterName=cluster_name, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, cluster_name))

    asg_name = ctx.unique_name("sim2real-cp-scale-asg-")

    def _try_create_asg():
        try:
            autoscaling.create_auto_scaling_group(
                AutoScalingGroupName=asg_name,
                LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
                MinSize=0,
                MaxSize=2,
                DesiredCapacity=0,
                VPCZoneIdentifier=",".join(subnet_ids),
                Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
            )
            return True
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            message = exc.response.get("Error", {}).get("Message", "")
            if code == "ValidationError" and "Instance Profile" in message:
                return False
            raise

    # The instance profile is visible via IAM's own API (polled above), but IAM changes
    # propagate to the EC2/Auto Scaling control plane on their own lag, so
    # CreateAutoScalingGroup can still reject the launch template's iamInstanceProfile as
    # not-yet-resolvable for a short window. Retry only that specific rejection.
    _poll_until(_try_create_asg, lambda ok: ok is True, timeout_s=60.0, interval_s=5.0)
    ctx.on_cleanup(
        lambda: autoscaling.delete_auto_scaling_group(
            AutoScalingGroupName=asg_name, ForceDelete=True
        )
    )
    initial = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ][0]
    assert initial["DesiredCapacity"] == 0, f"expected ASG to start at 0: {initial}"
    asg_arn = initial["AutoScalingGroupARN"]

    cp_name = ctx.unique_name("sim2real-cp-scale-provider-")
    ecs.create_capacity_provider(
        name=cp_name,
        autoScalingGroupProvider={
            "autoScalingGroupArn": asg_arn,
            "managedScaling": {
                "status": "ENABLED",
                "targetCapacity": 100,
                "minimumScalingStepSize": 1,
                "maximumScalingStepSize": 1,
                "instanceWarmupPeriod": 60,
            },
            "managedTerminationProtection": "DISABLED",
        },
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: _retry_while_cluster_busy(lambda: ecs.delete_capacity_provider(capacityProvider=cp_name)))
    ctx.on_cleanup(
        lambda: _retry_while_cluster_busy(lambda: ecs.put_cluster_capacity_providers(
            cluster=cluster_name, capacityProviders=[], defaultCapacityProviderStrategy=[]
        ))
    )
    ecs.put_cluster_capacity_providers(
        cluster=cluster_name,
        capacityProviders=[cp_name],
        defaultCapacityProviderStrategy=[{"capacityProvider": cp_name, "weight": 1, "base": 0}],
    )

    family = ctx.unique_name("sim2real-cp-scale-taskdef-")
    task_def_arn = ecs.register_task_definition(
        family=family,
        networkMode="bridge",
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023-minimal",
                "cpu": 128,
                "memory": 128,
                "essential": True,
                "command": ["sleep", "3600"],
            }
        ],
        tags=[{"key": "sim2real", "value": CHECK}],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))

    service_name = ctx.unique_name("sim2real-cp-scale-svc-")
    created = ecs.create_service(
        cluster=cluster_name,
        serviceName=service_name,
        taskDefinition=family,
        desiredCount=1,
        capacityProviderStrategy=[{"capacityProvider": cp_name, "weight": 1}],
    )["service"]
    assert created["desiredCount"] == 1, f"service did not record desiredCount=1: {created}"
    ctx.on_cleanup(
        lambda: ecs.delete_service(cluster=cluster_name, service=service_name, force=True)
    )

    scaled = _poll_until(
        lambda: autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
            "AutoScalingGroups"
        ][0],
        lambda g: g["DesiredCapacity"] >= 1,
        timeout_s=600.0,
        interval_s=15.0,
    )
    assert scaled["DesiredCapacity"] >= 1, (
        f"expected ECS managed scaling to raise the ASG desired capacity above 0 to "
        f"satisfy the unplaced service task, got {scaled}"
    )


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


def _ecs_optimized_ami_id(ssm):
    value = ssm.get_parameter(Name="/aws/service/ecs/optimized-ami/amazon-linux-2/recommended")[
        "Parameter"
    ]["Value"]
    return json.loads(value)["image_id"]


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


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


def _retire_task_definition(ecs, task_definition: str) -> None:
    """Deregister a task definition revision, then delete it: a deregistered revision stays
    INACTIVE until DeleteTaskDefinitions removes it. An already-deleted revision is fine; any
    other failure raises."""
    from botocore.exceptions import ClientError

    try:
        described = ecs.describe_task_definition(taskDefinition=task_definition)["taskDefinition"]
    except ClientError as exc:
        if "Unable to describe task definition" in exc.response["Error"].get("Message", ""):
            return
        raise
    arn = described["taskDefinitionArn"]
    if described["status"] == "DELETE_IN_PROGRESS":
        return
    if described["status"] == "ACTIVE":
        ecs.deregister_task_definition(taskDefinition=arn)
    failures = ecs.delete_task_definitions(taskDefinitions=[arn]).get("failures", [])
    if failures:
        raise RuntimeError(f"task definition {arn} teardown failed: {failures}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
