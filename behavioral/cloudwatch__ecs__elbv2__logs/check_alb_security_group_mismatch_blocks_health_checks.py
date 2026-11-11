"""alb-security-group-mismatch-blocks-health-checks."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "alb-security-group-mismatch-blocks-health-checks"
GROUP = "permission-boundary"
SERVICES = ["cloudwatch", "ecs", "elbv2", "logs"]

_EXEC_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
_IMAGE = "public.ecr.aws/docker/library/nginx:alpine"


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Negative: an ECS task security group with no ingress rule from the ALB's security group
    leaves the target unhealthy and the ALB serving 503s, so the security group is the blocker."""
    vpc_id, subnets = _default_vpc_and_subnets(ctx)
    subnet_ids = [s["SubnetId"] for s in subnets]

    alb_sg = _create_sg(ctx, vpc_id, "alb ingress")
    _authorize_ingress_cidr(ctx, alb_sg, 80, ctx.ingress_cidrs())

    isolated_sg = _create_sg(ctx, vpc_id, "task sg with no ingress rules at all")
    # deliberately no authorize_security_group_ingress call: default outbound
    # allow-all, but zero inbound rules -- the ALB cannot reach the task.

    alb_arn, dns = _create_alb(ctx, subnet_ids, alb_sg)
    tg_arn = _create_target_group(ctx, vpc_id, 80, "/")
    _create_listener(ctx, alb_arn, [{"Type": "forward", "TargetGroupArn": tg_arn}])

    exec_role_arn = _create_exec_role(ctx)
    log_group = _create_log_group(ctx)
    cluster = _create_cluster(ctx)

    marker = "sim2real-sg-fixed"
    task_def_arn = _register_task_def(
        ctx, _IMAGE, 80, exec_role_arn, log_group,
        command=["/bin/sh", "-c", f"echo -n {marker} > /usr/share/nginx/html/index.html && exec nginx -g 'daemon off;'"],
    )
    service_name = _create_service(ctx, cluster, task_def_arn, subnet_ids, [isolated_sg], desired_count=1, target_group_arn=tg_arn)
    _wait_running_count(ctx, cluster, service_name, 1)

    # Effect: over a bounded monitoring window, the target must never reach
    # "healthy" (whether it's still "initial" or has flipped to "unhealthy" is
    # immaterial -- ALB activation timing varies run to run, but "never
    # healthy while the SG blocks ingress" is the invariant we're proving),
    # and the ALB must never serve a 200 for a target it can't reach.
    deadline = time.monotonic() + 120.0

    saw_non_initial = False
    last_states = []
    while time.monotonic() < deadline:
        elbv2 = ctx.client("elbv2")
        resp = elbv2.describe_target_health(TargetGroupArn=tg_arn)
        last_states = [
            {"id": d["Target"]["Id"], "state": d["TargetHealth"]["State"], "reason": d["TargetHealth"].get("Reason")}
            for d in resp["TargetHealthDescriptions"]
        ]
        for t in last_states:
            assert t["state"] != "healthy", f"target became healthy despite SG blocking ALB ingress: {t}"
            if t["state"] != "initial":
                saw_non_initial = True
        status, _body = _http_get(ctx, f"http://{dns}/")
        assert status != 200, f"ALB served 200 for an unreachable target (status={status})"
        if saw_non_initial:
            break
        time.sleep(5.0)

    assert last_states, "target was never registered in the target group"
    assert saw_non_initial, (
        f"target never progressed past 'initial' within the monitoring window: {last_states}"
    )
    assert last_states[0]["state"] == "unhealthy", f"unexpected terminal state: {last_states}"


# ===== helpers =====

def _short_id() -> str:
    return uuid.uuid4().hex[:8]


def _poll_until(probe, predicate, timeout_s=300.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last state={last!r}")


def _http_get(ctx, url, headers=None, timeout=5.0):
    target, route = ctx.endpoint_route(url)
    req = urllib.request.Request(target, headers={**(headers or {}), **route})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, ConnectionError):
        # A target the ALB cannot reach (this check's own subject) can also fail after the
        # TCP connect succeeds -- a read timeout or reset while ALB is still trying its own
        # backend connection -- which urllib does not wrap in URLError. Both are "no response".
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
    group_id = ec2.create_security_group(GroupName=name, Description=description, VpcId=vpc_id)["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group_when_free(ec2, group_id))
    return group_id


def _authorize_ingress_cidr(ctx, group_id, port, cidrs):
    ec2 = ctx.client("ec2")
    ec2.authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": port, "ToPort": port, "IpRanges": [{"CidrIp": c} for c in cidrs]}],
    )


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
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_EXEC_POLICY_ARN)

    def _cleanup():
        iam.detach_role_policy(RoleName=role_name, PolicyArn=_EXEC_POLICY_ARN)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    # No fixed sleep for IAM role propagation: a task launched before the exec role has
    # propagated fails to start, and the ECS service scheduler retries the launch on its
    # own, so the bounded _wait_running_count poll that follows already absorbs that delay.
    return role_arn


def _create_log_group(ctx):
    logs = ctx.client("logs")
    name = f"/ecs/sim2real-{_short_id()}"
    logs.create_log_group(logGroupName=name)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=name))
    return name


def _create_cluster(ctx):
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-cluster-")
    ecs.create_cluster(clusterName=name)
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
        kwargs["healthCheckGracePeriodSeconds"] = 900

    ecs.create_service(**kwargs)
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=cluster, service=service_name, force=True))
    return service_name


def _wait_running_count(ctx, cluster, service_name, want, timeout_s=420.0, interval_s=15.0):
    ecs = ctx.client("ecs")

    def probe():
        d = ecs.describe_services(cluster=cluster, services=[service_name])["services"][0]
        return d["runningCount"]

    return _poll_until(probe, lambda v: v >= want, timeout_s=timeout_s, interval_s=interval_s)


def _create_alb(ctx, subnets, sg_id):
    elbv2 = ctx.client("elbv2")
    name = f"sim2real-alb-{_short_id()}"
    resp = elbv2.create_load_balancer(
        Name=name, Subnets=subnets, SecurityGroups=[sg_id], Scheme="internet-facing", Type="application", IpAddressType="ipv4",
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
        HealthCheckIntervalSeconds=5, HealthyThresholdCount=2, UnhealthyThresholdCount=2,
        HealthCheckTimeoutSeconds=2,
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _delete_target_group_when_free(elbv2, tg_arn))
    return tg_arn


def _create_listener(ctx, alb_arn, default_actions, port=80):
    elbv2 = ctx.client("elbv2")
    listener_arn = elbv2.create_listener(LoadBalancerArn=alb_arn, Protocol="HTTP", Port=port, DefaultActions=default_actions)["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_listener(ListenerArn=listener_arn))
    return listener_arn


def _wait_target_states(ctx, tg_arn, timeout_s=300.0, interval_s=10.0, predicate=lambda states: True):
    elbv2 = ctx.client("elbv2")

    def probe():
        resp = elbv2.describe_target_health(TargetGroupArn=tg_arn)
        return [
            {"id": d["Target"]["Id"], "port": d["Target"]["Port"], "state": d["TargetHealth"]["State"], "reason": d["TargetHealth"].get("Reason")}
            for d in resp["TargetHealthDescriptions"]
        ]

    return _poll_until(probe, predicate, timeout_s=timeout_s, interval_s=interval_s)


def _wait_lb_active(ctx, alb_arn, timeout_s=180.0, interval_s=10.0):
    elbv2 = ctx.client("elbv2")

    def probe():
        return elbv2.describe_load_balancers(LoadBalancerArns=[alb_arn])["LoadBalancers"][0]["State"]["Code"]

    return _poll_until(probe, lambda c: c == "active", timeout_s=timeout_s, interval_s=interval_s)


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
