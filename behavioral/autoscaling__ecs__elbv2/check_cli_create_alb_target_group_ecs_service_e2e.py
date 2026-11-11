"""cli-create-alb-target-group-ecs-service-e2e."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time

from fidelity_tests_runner import require_tools

from behavioral_harness import tags

CHECK = "cli-create-alb-target-group-ecs-service-e2e"
GROUP = "cli-workflow"
SERVICES = ["autoscaling", "ecs", "elbv2"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """An ALB, IP target group and Fargate service created through the AWS CLI register exactly the
    running task's ENI private IP as the target group's target."""
    require_tools("aws")

    vpc_id, subnet_ids = _default_vpc_subnets(ctx)
    sg_id = _create_sg(ctx, vpc_id)
    execution_role_arn = _create_execution_role(ctx)
    cluster_arn = _create_cluster(ctx)
    container_name = "web"
    container_port = 80
    task_def_arn = _register_task_def(ctx, execution_role_arn, container_name, container_port)

    alb_name = ctx.unique_name("sim2real-alb-")
    tg_name = ctx.unique_name("sim2real-tg-")
    cluster_name = cluster_arn.split("/")[-1]
    service_name = ctx.unique_name("sim2real-svc-")

    tg_out = _run_aws(
        ctx, "elbv2", "create-target-group",
        "--name", tg_name, "--protocol", "HTTP", "--port", str(container_port),
        "--vpc-id", vpc_id, "--target-type", "ip",
        "--health-check-path", "/", "--health-check-interval-seconds", "10",
        "--healthy-threshold-count", "2", "--unhealthy-threshold-count", "2",
    )
    tg_arn = tg_out["TargetGroups"][0]["TargetGroupArn"]
    elbv2 = ctx.client("elbv2")
    ctx.on_cleanup(lambda: _delete_target_group_when_free(elbv2, tg_arn))

    alb_out = _run_aws(
        ctx, "elbv2", "create-load-balancer",
        "--name", alb_name, "--subnets", *subnet_ids, "--security-groups", sg_id,
        "--scheme", "internet-facing", "--type", "application",
    )
    alb_arn = alb_out["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=alb_arn))
    _poll_until(
        lambda: elbv2.describe_load_balancers(LoadBalancerArns=[alb_arn])["LoadBalancers"][0]["State"]["Code"],
        lambda s: s == "active",
        timeout_s=300, interval_s=10, desc="ALB to become active",
    )

    listener_out = _run_aws(
        ctx, "elbv2", "create-listener",
        "--load-balancer-arn", alb_arn, "--protocol", "HTTP", "--port", "80",
        "--default-actions", f"Type=forward,TargetGroupArn={tg_arn}",
    )
    listener_arn = listener_out["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_listener(ListenerArn=listener_arn))

    net_cfg = json.dumps(
        {"awsvpcConfiguration": {"subnets": subnet_ids, "securityGroups": [sg_id], "assignPublicIp": "ENABLED"}}
    )
    _run_aws(
        ctx, "ecs", "create-service",
        "--cluster", cluster_name, "--service-name", service_name,
        "--task-definition", task_def_arn, "--desired-count", "1", "--launch-type", "FARGATE",
        "--network-configuration", net_cfg,
        "--load-balancers", f"targetGroupArn={tg_arn},containerName={container_name},containerPort={container_port}",
    )
    ecs = ctx.client("ecs")

    def _cleanup_service():
        from botocore.exceptions import ClientError

        try:
            ecs.update_service(cluster=cluster_arn, service=service_name, desiredCount=0)
            ecs.delete_service(cluster=cluster_arn, service=service_name, force=True)
        except ClientError as exc:
            gone = ("ServiceNotFoundException", "ServiceNotActiveException", "ClusterNotFoundException")
            if exc.response["Error"]["Code"] not in gone:
                raise

    ctx.on_cleanup(_cleanup_service)

    _poll_until(
        lambda: ecs.describe_services(cluster=cluster_arn, services=[service_name])["services"][0]["runningCount"],
        lambda n: n >= 1, timeout_s=420, interval_s=15, desc="ECS service running count",
    )

    task_arns = ecs.list_tasks(cluster=cluster_arn, serviceName=service_name, desiredStatus="RUNNING")["taskArns"]
    assert task_arns, "service is running but no RUNNING tasks were found"
    described = ecs.describe_tasks(cluster=cluster_arn, tasks=task_arns)["tasks"]
    task_ips = set()
    for t in described:
        for att in t.get("attachments", []):
            for detail in att.get("details", []):
                if detail["name"] == "privateIPv4Address":
                    task_ips.add(detail["value"])
    assert task_ips, "no ENI private IPs found on the running task(s)"

    targets = _poll_until(
        lambda: elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"],
        lambda t: len(t) >= 1, timeout_s=180, interval_s=10, desc="task ENI registered as a target",
    )
    target_ids = {t["Target"]["Id"] for t in targets}
    assert target_ids == task_ips, f"target group targets {target_ids} != running task ENI IPs {task_ips}"
    target_ports = {t["Target"]["Port"] for t in targets}
    assert target_ports == {container_port}, f"target ports {target_ports} != container port {{{container_port}}}"


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        command, shell=isinstance(command, str), env=env, capture_output=True, text=True,
        timeout=timeout_s, cwd=cwd,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"Command failed (rc={result.returncode}):\n  cmd: {command}\n  stderr: {result.stderr[-500:]}"
        )
    return result


def _run_script(ctx, script: str, *, timeout_s=120.0, check=True, env_extra=None):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
        f.write("#!/bin/bash\nset -euo pipefail\n")
        f.write(script)
        script_path = f.name
    try:
        os.chmod(script_path, 0o755)
        return _run_shell(ctx, ["bash", script_path], timeout_s=timeout_s, check=check, env_extra=env_extra)
    finally:
        os.unlink(script_path)


def _run_aws(ctx, *args: str, timeout_s=60.0, check=True):
    proc = _run_shell(ctx, ["aws", "--output", "json", *args], timeout_s=timeout_s, check=check)
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


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
        GroupName=name, Description="sim2real ecs/elbv2 behavioral check", VpcId=vpc_id,
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
    # No unconditional wait here: if the trust policy has not yet propagated when Fargate
    # first tries to assume it, the service scheduler retries task launch on its own, and
    # that retry is already bounded by the runningCount poll below (timeout_s=420).
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
        family=family, networkMode="awsvpc", requiresCompatibilities=["FARGATE"],
        cpu="256", memory="512", executionRoleArn=execution_role_arn,
        containerDefinitions=[{
            "name": container_name, "image": "public.ecr.aws/docker/library/httpd:2.4",
            "portMappings": [{"containerPort": container_port, "protocol": "tcp"}], "essential": True,
        }],
    )
    arn = resp["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, arn))
    return arn


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
