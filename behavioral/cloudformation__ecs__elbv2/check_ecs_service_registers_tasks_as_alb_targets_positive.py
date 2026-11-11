"""ecs-service-registers-tasks-as-alb-targets-positive."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "ecs-service-registers-tasks-as-alb-targets-positive"
GROUP = "resource-binding"
SERVICES = ["cloudformation", "ecs", "elbv2"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """ECS-managed Fargate tasks register as healthy ALB targets shortly after stabilization."""
    net = _create_network(ctx)
    exec_role_arn = _create_execution_role(ctx)
    cluster_arn = _create_cluster(ctx)
    td_arn = _register_task_def(ctx, exec_role_arn, "web", "public.ecr.aws/docker/library/httpd:latest", 80)
    alb = _create_alb(ctx, net["subnet_ids"], net["sg_id"])
    tg_arn = _create_target_group(ctx, net["vpc_id"])
    _create_listener(ctx, alb["arn"], tg_arn)
    svc = _create_service(
        ctx, cluster_arn, td_arn, net["subnet_ids"], net["sg_id"],
        desired_count=2, tg_arn=tg_arn, container_name="web", container_port=80,
    )
    _wait_service_stable(ctx, cluster_arn, svc["name"])

    task_arns = _list_running_task_arns(ctx, cluster_arn, svc["name"])
    assert len(task_arns) == 2, f"expected 2 running tasks, ListTasks returned {len(task_arns)}: {task_arns}"
    task_ips = {_task_private_ip(ctx, cluster_arn, t) for t in task_arns}

    descs = _poll_until(
        lambda: _target_health(ctx, tg_arn),
        lambda ds: len(ds) == 2 and all(d["TargetHealth"]["State"] == "healthy" for d in ds),
        timeout_s=240, interval_s=10,
    )
    target_ips = {d["Target"]["Id"] for d in descs}
    assert target_ips == task_ips, f"registered target IPs {target_ips} != task ENI IPs {task_ips}"
    for d in descs:
        assert d["Target"]["Port"] == 80, f"expected target port 80, got {d['Target']['Port']} for {d['Target']['Id']}"


# ===== helpers =====
_PREFIX = "sim2real-ecsalb-"


def _name(ctx, kind: str) -> str:
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_network(ctx):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"][0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    subnet_ids = [s["SubnetId"] for s in subnets[:2]]
    sg_id = ec2.create_security_group(
        GroupName=_name(ctx, "sg"), Description="sim2real ecs-alb shared sg", VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "sim2real", "Value": "true"}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group_when_free(ec2, sg_id))
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 0, "ToPort": 65535, "UserIdGroupPairs": [{"GroupId": sg_id}]}],
    )
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids, "sg_id": sg_id}


def _create_execution_role(ctx):
    iam = ctx.client("iam")
    role_name = _name(ctx, "exec-role")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    })
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role_arn


def _create_cluster(ctx):
    ecs = ctx.client("ecs")
    arn = ecs.create_cluster(
        clusterName=_name(ctx, "cluster"), tags=[{"key": "sim2real", "value": "true"}],
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, arn))
    return arn


def _register_task_def(ctx, exec_role_arn, container_name, image, container_port, command=None):
    ecs = ctx.client("ecs")
    container = {
        "name": container_name,
        "image": image,
        "essential": True,
        "portMappings": [{"containerPort": container_port, "protocol": "tcp"}],
    }
    if command:
        container["command"] = command
    resp = ecs.register_task_definition(
        family=_name(ctx, "taskdef"),
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        executionRoleArn=exec_role_arn,
        containerDefinitions=[container],
        tags=[{"key": "sim2real", "value": "true"}],
    )
    td_arn = resp["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_def(ecs, td_arn))
    return td_arn


def _retire_task_def(ecs, arn: str) -> None:
    """Deregister, then delete, one task definition revision, so no INACTIVE revision lingers."""
    ecs.deregister_task_definition(taskDefinition=arn)
    failures = ecs.delete_task_definitions(taskDefinitions=[arn]).get("failures") or []
    if failures:
        raise RuntimeError(f"DeleteTaskDefinitions refused {arn}: {failures!r}")


def _create_alb(ctx, subnet_ids, sg_id):
    elbv2 = ctx.client("elbv2")
    resp = elbv2.create_load_balancer(
        Name=_name(ctx, "alb"), Subnets=subnet_ids, SecurityGroups=[sg_id],
        Scheme="internet-facing", Type="application", IpAddressType="ipv4",
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    alb_arn = resp["LoadBalancers"][0]["LoadBalancerArn"]
    alb_dns = resp["LoadBalancers"][0]["DNSName"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=alb_arn))
    _poll_until(
        lambda: elbv2.describe_load_balancers(LoadBalancerArns=[alb_arn])["LoadBalancers"][0]["State"]["Code"],
        lambda s: s == "active",
        timeout_s=240, interval_s=10,
    )
    return {"arn": alb_arn, "dns": alb_dns}


def _create_target_group(ctx, vpc_id, port=80, target_type="ip", health_check_path="/",
                          interval=10, healthy_threshold=2, unhealthy_threshold=2,
                          deregistration_delay=None):
    elbv2 = ctx.client("elbv2")
    timeout = max(2, min(interval - 1, 5))
    tg_arn = elbv2.create_target_group(
        Name=_name(ctx, "tg"), Protocol="HTTP", Port=port, VpcId=vpc_id, TargetType=target_type,
        HealthCheckProtocol="HTTP", HealthCheckPath=health_check_path,
        HealthCheckIntervalSeconds=interval, HealthCheckTimeoutSeconds=timeout,
        HealthyThresholdCount=healthy_threshold, UnhealthyThresholdCount=unhealthy_threshold,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _delete_target_group_when_free(elbv2, tg_arn))
    if deregistration_delay is not None:
        elbv2.modify_target_group_attributes(
            TargetGroupArn=tg_arn,
            Attributes=[{"Key": "deregistration_delay.timeout_seconds", "Value": str(deregistration_delay)}],
        )
    return tg_arn


def _create_listener(ctx, alb_arn, tg_arn, port=80):
    elbv2 = ctx.client("elbv2")
    listener_arn = elbv2.create_listener(
        LoadBalancerArn=alb_arn, Protocol="HTTP", Port=port,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_listener(ListenerArn=listener_arn))
    return listener_arn


def _create_service(ctx, cluster_arn, task_def_arn, subnet_ids, sg_id, desired_count=1,
                     tg_arn=None, container_name=None, container_port=None, grace_period=None):
    ecs = ctx.client("ecs")
    name = _name(ctx, "svc")
    kwargs = dict(
        cluster=cluster_arn, serviceName=name, taskDefinition=task_def_arn,
        desiredCount=desired_count, launchType="FARGATE",
        networkConfiguration={"awsvpcConfiguration": {
            "subnets": subnet_ids, "securityGroups": [sg_id], "assignPublicIp": "ENABLED",
        }},
        tags=[{"key": "sim2real", "value": "true"}],
    )
    if tg_arn:
        kwargs["loadBalancers"] = [{
            "targetGroupArn": tg_arn, "containerName": container_name, "containerPort": container_port,
        }]
    if grace_period is not None:
        kwargs["healthCheckGracePeriodSeconds"] = grace_period
    svc_arn = _create_service_with_role_retry(ecs, **kwargs)["service"]["serviceArn"]

    def _cleanup():
        try:
            ecs.update_service(cluster=cluster_arn, service=name, desiredCount=0)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "ClusterNotFoundException",
                "NamespaceNotFoundException",
                "ServiceNotFoundException",
            ):
                raise
        try:
            ecs.delete_service(cluster=cluster_arn, service=name, force=True)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "ClusterNotFoundException",
                "ServiceNotFoundException",
            ):
                raise

    ctx.on_cleanup(_cleanup)
    return {"arn": svc_arn, "name": name}


def _create_service_with_role_retry(ecs, timeout_s=60.0, **kwargs):
    """IAM roles are eventually consistent; CreateService can synchronously fail with
    ClientException("... unable to assume the role ...") for a short window right after the
    execution role's CreateRole/AttachRolePolicy. Retry on that specific error instead of an
    unconditional sleep before the call."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return ecs.create_service(**kwargs)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            msg = str(err)
            last_err = err
            if code in ("ClientException", "InvalidParameterException") and "ssume" in msg.lower():
                time.sleep(5)
                continue
            raise
    raise last_err if last_err is not None else RuntimeError("CreateService never succeeded")


def _wait_service_stable(ctx, cluster_arn, service_name, timeout_s=420):
    ecs = ctx.client("ecs")
    waiter = ecs.get_waiter("services_stable")
    waiter.wait(cluster=cluster_arn, services=[service_name],
                WaiterConfig={"Delay": 2, "MaxAttempts": max(1, timeout_s // 2)})


def _list_running_task_arns(ctx, cluster_arn, service_name):
    ecs = ctx.client("ecs")
    return ecs.list_tasks(cluster=cluster_arn, serviceName=service_name, desiredStatus="RUNNING")["taskArns"]


def _target_health(ctx, tg_arn):
    elbv2 = ctx.client("elbv2")
    return elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]


def _task_private_ip(ctx, cluster_arn, task_arn):
    ecs = ctx.client("ecs")
    task = ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])["tasks"][0]
    for att in task.get("attachments", []):
        if att.get("type") == "ElasticNetworkInterface":
            for d in att.get("details", []):
                if d["name"] == "privateIPv4Address":
                    return d["value"]
    raise AssertionError(f"no ENI private IP found for task {task_arn}")


def _drain_and_delete_ecs_cluster(ecs, cluster, timeout_s=900.0, interval_s=2.0):
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
                    "ClusterNotFoundException", "ServiceNotFoundException", "ServiceNotActiveException",
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


def _delete_security_group_when_free(ec2, sg_id, timeout_s=900.0, interval_s=2.0):
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


def _delete_target_group_when_free(elbv2, arn, timeout_s=600.0, interval_s=2.0):
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
