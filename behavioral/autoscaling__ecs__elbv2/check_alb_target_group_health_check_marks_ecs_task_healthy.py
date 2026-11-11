"""alb-target-group-health-check-marks-ecs-task-healthy."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "alb-target-group-health-check-marks-ecs-task-healthy"
GROUP = "resource-binding"
SERVICES = ["autoscaling", "ecs", "elbv2"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A target group's HTTP health check against an ECS/Fargate task's container port
    transitions the ENI target from initial -> healthy once the task is actually serving."""
    stack = _provision(ctx, desired_count=1)

    _wait_service_running(ctx, stack["cluster_arn"], stack["service_name"], 1)

    states = _poll_until(
        lambda: [t["TargetHealth"]["State"] for t in _target_health(ctx, stack["tg_arn"])],
        lambda states: len(states) == 1 and states[0] == "healthy",
        timeout_s=300,
        interval_s=10,
        desc="ECS task target to become healthy",
    )
    assert states == ["healthy"], (
        f"expected the ALB target group to report the ECS/Fargate task's target as healthy, got {states!r}"
    )


def _poll_until(probe, predicate, *, timeout_s, interval_s, desc):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {desc}; last observed: {last!r}")


def _default_vpc_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC in this account/region to attach the ALB/ECS test resources to")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    public = [s["SubnetId"] for s in subnets if s.get("MapPublicIpOnLaunch")]
    chosen = (public if len(public) >= 2 else [s["SubnetId"] for s in subnets])[:2]
    if len(chosen) < 2:
        raise AssertionError("shared network does not have at least two subnets across AZs")
    return vpc_id, chosen


def _create_sg(ctx, vpc_id):
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-ecs-elb-sg-")
    sg_id = ec2.create_security_group(
        GroupName=name,
        Description="sim2real ecs/elbv2 behavioral check",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": name}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group_when_free(ec2, sg_id))
    ec2.authorize_security_group_ingress(
        GroupId=sg_id, IpPermissions=[{"IpProtocol": "-1", "UserIdGroupPairs": [{"GroupId": sg_id}]}]
    )
    return sg_id


def _create_execution_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ecs-exec-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    # No fixed wait here: IAM propagation is absorbed by _wait_service_running's own
    # bounded poll below -- the ECS service scheduler retries a task that fails to
    # start (including a not-yet-assumable execution role) on its own, well inside
    # that poll's 420s deadline.
    return role_arn


def _create_cluster(ctx):
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-ecs-cluster-")
    arn = ecs.create_cluster(clusterName=name)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, arn))
    return arn


def _register_task_def(ctx, execution_role_arn, container_name="web", container_port=80):
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-ecs-taskdef-")
    resp = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        executionRoleArn=execution_role_arn,
        containerDefinitions=[
            {
                "name": container_name,
                "image": "public.ecr.aws/docker/library/httpd:2.4",
                "portMappings": [{"containerPort": container_port, "protocol": "tcp"}],
                "essential": True,
            }
        ],
    )
    arn = resp["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, arn))
    return arn


def _create_target_group(ctx, vpc_id, port=80, health_check_port=None, interval=10, dereg_delay_s=None):
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-tg-")
    kwargs: dict[str, Any] = dict(
        Name=name,
        Protocol="HTTP",
        Port=port,
        VpcId=vpc_id,
        TargetType="ip",
        HealthCheckProtocol="HTTP",
        HealthCheckPath="/",
        HealthCheckIntervalSeconds=interval,
        HealthyThresholdCount=2,
        UnhealthyThresholdCount=2,
    )
    if health_check_port is not None:
        kwargs["HealthCheckPort"] = str(health_check_port)
    tg_arn = elbv2.create_target_group(**kwargs)["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _delete_target_group_when_free(elbv2, tg_arn))
    if dereg_delay_s is not None:
        elbv2.modify_target_group_attributes(
            TargetGroupArn=tg_arn,
            Attributes=[{"Key": "deregistration_delay.timeout_seconds", "Value": str(dereg_delay_s)}],
        )
    return tg_arn


def _create_alb(ctx, subnet_ids, sg_id):
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-alb-")
    alb_arn = elbv2.create_load_balancer(
        Name=name, Subnets=subnet_ids, SecurityGroups=[sg_id], Scheme="internet-facing", Type="application"
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=alb_arn))
    _poll_until(
        lambda: elbv2.describe_load_balancers(LoadBalancerArns=[alb_arn])["LoadBalancers"][0]["State"]["Code"],
        lambda s: s == "active",
        timeout_s=300,
        interval_s=10,
        desc="ALB to become active",
    )
    dns_name = elbv2.describe_load_balancers(LoadBalancerArns=[alb_arn])["LoadBalancers"][0]["DNSName"]
    return alb_arn, dns_name


def _create_listener(ctx, alb_arn, tg_arn, port=80):
    elbv2 = ctx.client("elbv2")
    return elbv2.create_listener(
        LoadBalancerArn=alb_arn,
        Protocol="HTTP",
        Port=port,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    )["Listeners"][0]["ListenerArn"]


def _create_service(ctx, cluster_arn, task_def_arn, tg_arn, subnet_ids, sg_id, container_name, container_port, desired_count=1):
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-ecs-svc-")
    ecs.create_service(
        cluster=cluster_arn,
        serviceName=name,
        taskDefinition=task_def_arn,
        desiredCount=desired_count,
        launchType="FARGATE",
        networkConfiguration={
            "awsvpcConfiguration": {"subnets": subnet_ids, "securityGroups": [sg_id], "assignPublicIp": "ENABLED"}
        },
        loadBalancers=[{"targetGroupArn": tg_arn, "containerName": container_name, "containerPort": container_port}],
    )

    def _cleanup():
        from botocore.exceptions import ClientError

        try:
            ecs.update_service(cluster=cluster_arn, service=name, desiredCount=0)
            ecs.delete_service(cluster=cluster_arn, service=name, force=True)
        except ClientError as exc:
            gone = ("ServiceNotFoundException", "ServiceNotActiveException", "ClusterNotFoundException")
            if exc.response["Error"]["Code"] not in gone:
                raise

    ctx.on_cleanup(_cleanup)
    return name


def _wait_service_running(ctx, cluster_arn, service_name, desired_count, timeout_s=420):
    ecs = ctx.client("ecs")

    def probe():
        d = ecs.describe_services(cluster=cluster_arn, services=[service_name])["services"][0]
        return d["runningCount"]

    return _poll_until(probe, lambda n: n >= desired_count, timeout_s=timeout_s, interval_s=15, desc="ECS service running count")


def _target_health(ctx, tg_arn):
    elbv2 = ctx.client("elbv2")
    return elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]


def _provision(ctx, *, desired_count=1, container_port=80, health_check_port=None, dereg_delay_s=None):
    vpc_id, subnet_ids = _default_vpc_subnets(ctx)
    sg_id = _create_sg(ctx, vpc_id)
    execution_role_arn = _create_execution_role(ctx)
    cluster_arn = _create_cluster(ctx)
    container_name = "web"
    task_def_arn = _register_task_def(ctx, execution_role_arn, container_name, container_port)
    tg_arn = _create_target_group(ctx, vpc_id, container_port, health_check_port, dereg_delay_s=dereg_delay_s)
    alb_arn, dns_name = _create_alb(ctx, subnet_ids, sg_id)
    _create_listener(ctx, alb_arn, tg_arn, port=80)
    service_name = _create_service(
        ctx, cluster_arn, task_def_arn, tg_arn, subnet_ids, sg_id, container_name, container_port, desired_count
    )
    return {
        "vpc_id": vpc_id,
        "subnet_ids": subnet_ids,
        "sg_id": sg_id,
        "cluster_arn": cluster_arn,
        "task_def_arn": task_def_arn,
        "tg_arn": tg_arn,
        "alb_arn": alb_arn,
        "dns_name": dns_name,
        "service_name": service_name,
        "container_name": container_name,
        "container_port": container_port,
    }


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


def _delete_security_group_when_free(ec2, sg_id, timeout_s=900.0, interval_s=15.0):
    """Delete a security group once the ENIs still holding it are released (DependencyViolation)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_security_group(GroupId=sg_id)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "InvalidGroup.NotFound":
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _delete_target_group_when_free(elbv2, arn, timeout_s=600.0, interval_s=10.0):
    """Delete a target group once no listener or deleting load balancer still uses it (ResourceInUse)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            elbv2.delete_target_group(TargetGroupArn=arn)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "TargetGroupNotFound":
                return
            if code != "ResourceInUse" or time.monotonic() >= deadline:
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
