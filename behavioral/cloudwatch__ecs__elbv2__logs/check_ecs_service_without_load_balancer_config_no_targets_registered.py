"""ecs-service-without-load-balancer-config-no-targets-registered."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "ecs-service-without-load-balancer-config-no-targets-registered"
GROUP = "permission-boundary"
SERVICES = ["cloudwatch", "ecs", "elbv2", "logs"]

_EXEC_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
_IMAGE = "public.ecr.aws/docker/library/nginx:alpine"


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Negative: an ECS service without a loadBalancers entry registers no target in the target
    group, while an identical service WITH that entry registers, so the target group and network
    path are not the blocker."""
    vpc_id, subnets = _default_vpc_and_subnets(ctx)
    subnet_ids = [s["SubnetId"] for s in subnets]

    alb_sg = _create_sg(ctx, vpc_id, "alb ingress")
    task_sg = _create_sg(ctx, vpc_id, "task ingress from alb")
    _authorize_ingress_sg(ctx, task_sg, 80, alb_sg)

    alb_arn, _dns = _create_alb(ctx, subnet_ids, alb_sg)
    tg_arn = _create_target_group(ctx, vpc_id, 80, "/")
    _create_listener(ctx, alb_arn, [{"Type": "forward", "TargetGroupArn": tg_arn}])

    exec_role_arn = _create_exec_role(ctx)
    log_group = _create_log_group(ctx)
    cluster = _create_cluster(ctx)
    task_def_arn = _register_task_def(ctx, _IMAGE, 80, exec_role_arn, log_group)

    elbv2 = ctx.client("elbv2")

    # Service A: no loadBalancers config at all.
    service_a = _create_service(ctx, cluster, task_def_arn, subnet_ids, [task_sg], desired_count=1, target_group_arn=None)
    _wait_running_count(ctx, cluster, service_a, 1)
    a_ip = _task_private_ip(ctx, cluster, service_a)

    # Effect absent while service A is the only thing running.
    targets = elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]
    assert targets == [], f"target group unexpectedly has targets with no bound service: {targets}"

    # Positive control: an otherwise-identical service, but WITH a loadBalancers
    # entry against the very same target group, does register a target.
    service_b = _create_service(ctx, cluster, task_def_arn, subnet_ids, [task_sg], desired_count=1, target_group_arn=tg_arn)
    _wait_running_count(ctx, cluster, service_b, 1)
    b_ip = _task_private_ip(ctx, cluster, service_b)

    states = _wait_target_states(ctx, tg_arn, timeout_s=180.0, interval_s=2.0, predicate=lambda s: len(s) >= 1)
    assert any(t["id"] == b_ip and t["port"] == 80 for t in states), (
        f"service with a loadBalancers config never registered its task: {states}"
    )
    # Barrier: B registered after A had been running longer, so A's absence now is not lag.
    assert not any(t["id"] == a_ip for t in states), (
        f"the task of the service without a loadBalancers config was registered: {states}"
    )


# ===== helpers =====

def _short_id() -> str:
    return uuid.uuid4().hex[:8]


def _poll_until(probe, predicate, timeout_s=300.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last state={last!r}")


def _http_get(url, headers=None, timeout=5.0):
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except urllib.error.URLError:
        return None, None


def _default_vpc_and_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("account/region has no shared network VPC to host the ALB+ECS stack")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
        ]
    )["Subnets"]
    if len(subnets) < 2:
        raise AssertionError("shared network needs network subnets in >= 2 AZs for an ALB")
    return vpc_id, subnets[:2]


def _create_sg(ctx, vpc_id, description):
    ec2 = ctx.client("ec2")
    name = f"sim2real-sg-{_short_id()}"
    group_id = ec2.create_security_group(
        GroupName=name,
        Description=description,
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": name}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group_when_free(ec2, group_id))
    return group_id


def _authorize_ingress_sg(ctx, group_id, port, source_group_id):
    ec2 = ctx.client("ec2")
    ec2.authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": port, "ToPort": port, "UserIdGroupPairs": [{"GroupId": source_group_id}]}],
    )


def _create_exec_role(ctx):
    iam = ctx.client("iam")
    role_name = f"sim2real-ecsexec-{_short_id()}"
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "Name", "Value": role_name}],
    )["Role"]["Arn"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_EXEC_POLICY_ARN)

    def _cleanup():
        iam.detach_role_policy(RoleName=role_name, PolicyArn=_EXEC_POLICY_ARN)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    # No unconditional wait here: IAM role propagation delay is absorbed by
    # _wait_running_count's own bounded retry, since ECS retries a task launch
    # that fails to assume a not-yet-propagated execution role.
    return role_arn


def _create_log_group(ctx):
    logs = ctx.client("logs")
    name = f"/ecs/sim2real-{_short_id()}"
    logs.create_log_group(logGroupName=name, tags={"sim2real": "true"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=name))
    return name


def _create_cluster(ctx):
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-cluster-")
    ecs.create_cluster(clusterName=name, tags=[{"key": "sim2real", "value": "true"}])
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, name))
    return name


def _register_task_def(ctx, image, container_port, exec_role_arn, log_group, command=None):
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-task-")
    container = {
        "name": "app",
        "image": image,
        "essential": True,
        "portMappings": [{"containerPort": container_port, "protocol": "tcp"}],
        "logConfiguration": {
            "logDriver": "awslogs",
            "options": {
                "awslogs-group": log_group,
                "awslogs-region": ctx.region,
                "awslogs-stream-prefix": "app",
            },
        },
    }
    if command:
        container["command"] = command
    resp = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        executionRoleArn=exec_role_arn,
        containerDefinitions=[container],
        tags=[{"key": "sim2real", "value": "true"}],
    )
    task_def_arn = resp["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))
    return task_def_arn


def _create_service(ctx, cluster, task_def_arn, subnets, sg_ids, desired_count=1, target_group_arn=None, container_name="app", container_port=80):
    ecs = ctx.client("ecs")
    service_name = ctx.unique_name("sim2real-svc-")
    kwargs = dict(
        cluster=cluster,
        serviceName=service_name,
        taskDefinition=task_def_arn,
        desiredCount=desired_count,
        launchType="FARGATE",
        networkConfiguration={
            "awsvpcConfiguration": {"subnets": subnets, "securityGroups": sg_ids, "assignPublicIp": "ENABLED"}
        },
    )
    if target_group_arn:
        kwargs["loadBalancers"] = [{"targetGroupArn": target_group_arn, "containerName": container_name, "containerPort": container_port}]
        kwargs["healthCheckGracePeriodSeconds"] = 90
    kwargs["tags"] = [{"key": "sim2real", "value": "true"}]
    ecs.create_service(**kwargs)
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=cluster, service=service_name, force=True))
    return service_name


def _wait_running_count(ctx, cluster, service_name, want, timeout_s=420.0, interval_s=2.0):
    ecs = ctx.client("ecs")

    def probe():
        d = ecs.describe_services(cluster=cluster, services=[service_name])["services"][0]
        return d["runningCount"]

    return _poll_until(probe, lambda v: v >= want, timeout_s=timeout_s, interval_s=interval_s)


def _task_private_ip(ctx, cluster, service_name):
    ecs = ctx.client("ecs")
    task_arns = ecs.list_tasks(cluster=cluster, serviceName=service_name, desiredStatus="RUNNING")["taskArns"]
    if not task_arns:
        raise AssertionError(f"no RUNNING tasks found for service {service_name}")
    task = ecs.describe_tasks(cluster=cluster, tasks=task_arns)["tasks"][0]
    return task["containers"][0]["networkInterfaces"][0]["privateIpv4Address"]


def _create_alb(ctx, subnets, sg_id):
    elbv2 = ctx.client("elbv2")
    name = f"sim2real-alb-{_short_id()}"
    resp = elbv2.create_load_balancer(
        Name=name, Subnets=subnets, SecurityGroups=[sg_id], Scheme="internet-facing", Type="application", IpAddressType="ipv4",
        Tags=[{"Key": "Name", "Value": name}],
    )
    lb = resp["LoadBalancers"][0]
    alb_arn, dns = lb["LoadBalancerArn"], lb["DNSName"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=alb_arn))
    return alb_arn, dns


def _create_target_group(ctx, vpc_id, port=80, health_path="/"):
    elbv2 = ctx.client("elbv2")
    name = f"sim2real-tg-{_short_id()}"
    tg_arn = elbv2.create_target_group(
        Name=name, Protocol="HTTP", Port=port, VpcId=vpc_id, TargetType="ip",
        HealthCheckProtocol="HTTP", HealthCheckPath=health_path,
        HealthCheckIntervalSeconds=10, HealthyThresholdCount=2, UnhealthyThresholdCount=2,
        HealthCheckTimeoutSeconds=5,
        Tags=[{"Key": "Name", "Value": name}],
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _delete_target_group_when_free(elbv2, tg_arn))
    return tg_arn


def _create_listener(ctx, alb_arn, default_actions, port=80):
    elbv2 = ctx.client("elbv2")
    listener_arn = elbv2.create_listener(LoadBalancerArn=alb_arn, Protocol="HTTP", Port=port, DefaultActions=default_actions)["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_listener(ListenerArn=listener_arn))
    return listener_arn


def _wait_target_states(ctx, tg_arn, timeout_s=300.0, interval_s=2.0, predicate=lambda states: True):
    elbv2 = ctx.client("elbv2")

    def probe():
        resp = elbv2.describe_target_health(TargetGroupArn=tg_arn)
        return [
            {"id": d["Target"]["Id"], "port": d["Target"]["Port"], "state": d["TargetHealth"]["State"], "reason": d["TargetHealth"].get("Reason")}
            for d in resp["TargetHealthDescriptions"]
        ]

    return _poll_until(probe, predicate, timeout_s=timeout_s, interval_s=interval_s)


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
                if exc.response["Error"]["Code"] not in (
                    "ServiceNotFoundException", "ServiceNotActiveException", "ClusterNotFoundException",
                ):
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
