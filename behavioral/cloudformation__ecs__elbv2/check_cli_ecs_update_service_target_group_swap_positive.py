"""cli-ecs-update-service-target-group-swap-positive."""
from __future__ import annotations

import json
import subprocess
import time

from behavioral_harness import tags
from fidelity_tests_runner import require_tools
from botocore.exceptions import ClientError

CHECK = "cli-ecs-update-service-target-group-swap-positive"
GROUP = "traffic-routing"
SERVICES = ["cloudformation", "ecs", "elbv2"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """`aws ecs update-service --load-balancers` swapping an existing rolling-update service to a
    new target group makes the new group receive a healthy target while the old group drains to
    zero, verified end-to-end via the ELBv2 SDK."""
    require_tools("aws")

    ecs = ctx.client("ecs")

    vpc_id, subnet_ids = _default_vpc_and_subnets(ctx)
    alb_sg, task_sg = _create_alb_and_task_sgs(ctx, vpc_id)
    execution_role_arn = _create_ecs_execution_role(ctx)
    cluster = _create_cluster(ctx)
    family, _task_def_arn = _register_task_def(ctx, execution_role_arn)

    alb_arn = _create_alb(ctx, vpc_id, subnet_ids, alb_sg, suffix="3")
    _wait_alb_active(ctx, alb_arn)
    tg1_arn = _create_target_group(ctx, vpc_id, suffix="3a", port=80)
    _attach_listener(ctx, alb_arn, tg1_arn, 80)
    tg2_arn = _create_target_group(ctx, vpc_id, suffix="3b", port=80)
    _attach_listener(ctx, alb_arn, tg2_arn, 8080)

    service_name = ctx.unique_name("sim2real-swapsvc-")
    ecs.create_service(
        cluster=cluster,
        serviceName=service_name,
        taskDefinition=family,
        desiredCount=1,
        launchType="FARGATE",
        loadBalancers=[{"targetGroupArn": tg1_arn, "containerName": "app", "containerPort": 80}],
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": subnet_ids,
                "securityGroups": [task_sg],
                "assignPublicIp": "ENABLED",
            }
        },
    )
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=cluster, service=service_name, force=True))

    healthy1 = _poll_until(
        lambda: [tid for tid, s in _target_states(ctx, tg1_arn) if s == "healthy"],
        lambda v: len(v) == 1,
        timeout_s=300,
        interval_s=15,
    )
    assert len(healthy1) == 1, f"expected exactly 1 healthy target on tg1, got {healthy1!r}"

    # swap the service's target group via the CLI
    _run_aws(
        ctx,
        "ecs",
        "update-service",
        "--cluster",
        cluster,
        "--service",
        service_name,
        "--load-balancers",
        f"targetGroupArn={tg2_arn},containerName=app,containerPort=80",
        "--force-new-deployment",
        timeout_s=60,
    )

    # the new target group becomes the one receiving traffic (a healthy target appears)
    healthy2 = _poll_until(
        lambda: [tid for tid, s in _target_states(ctx, tg2_arn) if s == "healthy"],
        lambda v: len(v) == 1,
        timeout_s=300,
        interval_s=15,
    )
    assert len(healthy2) == 1, f"expected exactly 1 healthy target on tg2 after the swap, got {healthy2!r}"

    # the old target group drains: its target is fully removed once the old task is stopped
    remaining_tg1 = _poll_until(
        lambda: _target_states(ctx, tg1_arn),
        lambda v: len(v) == 0,
        timeout_s=300,
        interval_s=15,
    )
    assert remaining_tg1 == [], f"expected tg1 fully drained after the swap, still has targets {remaining_tg1!r}"


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    env["AWS_PAGER"] = ""
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        command,
        shell=isinstance(command, str),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        cwd=cwd,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"Command failed (rc={result.returncode}):\n  cmd: {command}\n"
            f"  stderr: {result.stderr[-500:]}"
        )
    return result


def _run_aws(ctx, *args: str, timeout_s=30.0, check=True):
    proc = _run_shell(ctx, ["aws", "--output", "json", *args], timeout_s=timeout_s, check=check)
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _default_vpc_and_subnets(ctx, min_azs=2):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC in this account/region to host the ALB + Fargate task ENIs")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    by_az: dict = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())
    if len(subnet_ids) < min_azs:
        raise AssertionError(f"shared network has fewer than {min_azs} AZ-distinct network subnets")
    return vpc_id, subnet_ids[:min_azs]


def _create_alb_and_task_sgs(ctx, vpc_id):
    ec2 = ctx.client("ec2")

    def _tags(name):
        return [{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": name}]}]

    alb_sg_name = ctx.unique_name("sim2real-albsg-")
    alb_sg = ec2.create_security_group(
        GroupName=alb_sg_name, Description="alb sg", VpcId=vpc_id, TagSpecifications=_tags(alb_sg_name)
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group_when_free(ec2, alb_sg))

    task_sg_name = ctx.unique_name("sim2real-tasksg-")
    task_sg = ec2.create_security_group(
        GroupName=task_sg_name, Description="task sg", VpcId=vpc_id, TagSpecifications=_tags(task_sg_name)
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group_when_free(ec2, task_sg))
    ec2.authorize_security_group_ingress(
        GroupId=task_sg,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "UserIdGroupPairs": [{"GroupId": alb_sg}]}],
    )
    return alb_sg, task_sg


def _create_ecs_execution_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ecsexec-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    # bounded wait for the attachment to become visible on IAM's own read path, standing in for
    # the propagation lag before ECS can assume this role
    _poll_until(
        lambda: [p["PolicyArn"] for p in iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]],
        lambda arns: policy_arn in arns,
        timeout_s=60,
        interval_s=5,
    )
    return role_arn


def _create_cluster(ctx):
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-cluster-")
    ecs.create_cluster(clusterName=name)
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, name))
    return name


def _register_task_def(ctx, execution_role_arn, container_name="app", port=80):
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-taskdef-")
    resp = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        executionRoleArn=execution_role_arn,
        containerDefinitions=[
            {
                "name": container_name,
                "image": "public.ecr.aws/nginx/nginx:1.27",
                "portMappings": [{"containerPort": port, "protocol": "tcp"}],
                "essential": True,
            }
        ],
    )
    task_def_arn = resp["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_def(ecs, task_def_arn))
    return family, task_def_arn


def _retire_task_def(ecs, arn: str) -> None:
    """Deregister, then delete, one task definition revision, so no INACTIVE revision lingers."""
    ecs.deregister_task_definition(taskDefinition=arn)
    failures = ecs.delete_task_definitions(taskDefinitions=[arn]).get("failures") or []
    if failures:
        raise RuntimeError(f"DeleteTaskDefinitions refused {arn}: {failures!r}")


def _short_name(ctx, prefix, max_len=32):
    name = ctx.unique_name(prefix)
    if len(name) <= max_len:
        return name
    return name[-max_len:].lstrip("-")


def _create_alb(ctx, vpc_id, subnet_ids, alb_sg_id, suffix=""):
    elbv2 = ctx.client("elbv2")
    alb_name = _short_name(ctx, f"sim2real-alb{suffix}-")
    lb = elbv2.create_load_balancer(
        Name=alb_name,
        Subnets=subnet_ids,
        SecurityGroups=[alb_sg_id],
        Scheme="internet-facing",
        Type="application",
        IpAddressType="ipv4",
    )["LoadBalancers"][0]
    alb_arn = lb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=alb_arn))
    return alb_arn


def _create_target_group(ctx, vpc_id, suffix="", port=80):
    elbv2 = ctx.client("elbv2")
    tg_name = _short_name(ctx, f"sim2real-tg{suffix}-")
    tg_arn = elbv2.create_target_group(
        Name=tg_name,
        Protocol="HTTP",
        Port=port,
        VpcId=vpc_id,
        TargetType="ip",
        HealthCheckProtocol="HTTP",
        HealthCheckPath="/",
        HealthCheckIntervalSeconds=10,
        HealthyThresholdCount=2,
        UnhealthyThresholdCount=2,
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _delete_target_group_when_free(elbv2, tg_arn))
    # minimize the deregistration delay so the old target group's draining target is fully
    # removed within this check's poll window once the rolling update stops its task
    elbv2.modify_target_group_attributes(
        TargetGroupArn=tg_arn,
        Attributes=[{"Key": "deregistration_delay.timeout_seconds", "Value": "0"}],
    )
    return tg_arn


def _attach_listener(ctx, alb_arn, tg_arn, port):
    elbv2 = ctx.client("elbv2")
    listener_arn = elbv2.create_listener(
        LoadBalancerArn=alb_arn,
        Protocol="HTTP",
        Port=port,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_listener(ListenerArn=listener_arn))
    return listener_arn


def _wait_alb_active(ctx, alb_arn, timeout_s=180):
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = elbv2.describe_load_balancers(LoadBalancerArns=[alb_arn])["LoadBalancers"][0]["State"]["Code"]
        if state == "active":
            return
        time.sleep(2)
    raise AssertionError(f"ALB {alb_arn} never became active, last state={state}")


def _target_states(ctx, tg_arn):
    elbv2 = ctx.client("elbv2")
    descs = elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]
    return [(d["Target"]["Id"], d["TargetHealth"]["State"]) for d in descs]


def _poll_until(probe, predicate, *, timeout_s=300.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value={last!r}")


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
                # A service already deleted reads as not found or not active.
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
