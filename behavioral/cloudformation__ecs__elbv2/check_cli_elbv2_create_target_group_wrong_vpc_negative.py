"""cli-elbv2-create-target-group-wrong-vpc-negative."""

from __future__ import annotations

import json
import subprocess
import time

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-elbv2-create-target-group-wrong-vpc-negative"
GROUP = "resource-binding"
SERVICES = ["cloudformation", "ecs", "elbv2"]


@tags(
    "axis:negative-delivery",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A CLI-created target group in a VPC other than the ECS service's subnets never gets a
    healthy target from that service's Fargate task, while the identical task definition behind a
    target group in the service's own VPC becomes healthy (positive control)."""
    require_tools("aws")

    ecs = ctx.client("ecs")
    elbv2 = ctx.client("elbv2")

    vpc_a, subnet_ids_a = _shared_vpc_and_subnets(ctx)
    alb_sg_a, task_sg_a = _create_alb_and_task_sgs(ctx, vpc_a)
    execution_role_arn = _create_ecs_execution_role(ctx)
    cluster = _create_cluster(ctx)
    family, _task_def_arn = _register_task_def(ctx, execution_role_arn)

    vpc_b, subnet_ids_b, default_sg_b = _create_isolated_vpc(ctx)

    # a target group + its own internal ALB living entirely inside the OTHER (wrong) VPC, so it
    # genuinely gets health-checked -- just against a network it cannot route to the service's IP.
    alb_wrong_name = _short_name(ctx, "sim2real-wrongalb-")
    lb = elbv2.create_load_balancer(
        Name=alb_wrong_name,
        Subnets=subnet_ids_b,
        SecurityGroups=[default_sg_b],
        Scheme="internal",
        Type="application",
        IpAddressType="ipv4",
    )["LoadBalancers"][0]
    alb_wrong_arn = lb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=alb_wrong_arn))

    tg_wrong_name = _short_name(ctx, "sim2real-wrongtg-")
    result = _run_aws(
        ctx,
        "elbv2",
        "create-target-group",
        "--name",
        tg_wrong_name,
        "--protocol",
        "HTTP",
        "--port",
        "80",
        "--vpc-id",
        vpc_b,
        "--target-type",
        "ip",
        "--health-check-protocol",
        "HTTP",
        "--health-check-path",
        "/",
        "--healthy-threshold-count",
        "2",
        "--unhealthy-threshold-count",
        "2",
        "--health-check-interval-seconds",
        "10",
    )
    tg_wrong_arn = result["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _delete_target_group_when_free(elbv2, tg_wrong_arn))
    _attach_listener(ctx, alb_wrong_arn, tg_wrong_arn, 80)
    _wait_alb_active(ctx, alb_wrong_arn)

    # correct-VPC target group + ALB, both in vpc_a, for the positive control later.
    alb_correct_arn = _create_alb(ctx, vpc_a, subnet_ids_a, alb_sg_a, suffix="ok")
    tg_correct_arn = _create_target_group(ctx, vpc_a, suffix="ok")
    _attach_listener(ctx, alb_correct_arn, tg_correct_arn, 80)
    _wait_alb_active(ctx, alb_correct_arn)

    # the service under test: its tasks run in vpc_a's subnets but are load-balanced through the
    # wrong-VPC target group.
    service_name = ctx.unique_name("sim2real-wrongsvc-")
    ecs.create_service(
        cluster=cluster,
        serviceName=service_name,
        taskDefinition=family,
        desiredCount=1,
        launchType="FARGATE",
        loadBalancers=[
            {
                "targetGroupArn": tg_wrong_arn,
                "containerName": "app",
                "containerPort": 80,
            }
        ],
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": subnet_ids_a,
                "securityGroups": [task_sg_a],
                "assignPublicIp": "ENABLED",
            }
        },
    )
    ctx.on_cleanup(
        lambda: ecs.delete_service(cluster=cluster, service=service_name, force=True)
    )

    # the service launches its task. Whether that task then stays RUNNING is not the subject: ECS
    # registers the target while the task activates, and an IP outside the target group's VPC can
    # stop it there, so a task in any state counts as launched.
    def _launched_count():
        return sum(
            len(ecs.list_tasks(
                cluster=cluster, serviceName=service_name, desiredStatus=status
            )["taskArns"])
            for status in ("RUNNING", "STOPPED")
        )

    _poll_until(_launched_count, lambda v: v >= 1, timeout_s=300, interval_s=15)

    # effect absent: over a generous window, the wrong-VPC target group never reports "healthy".
    deadline = time.monotonic() + 240
    while time.monotonic() < deadline:
        states = [s for _, s in _target_states(ctx, tg_wrong_arn)]
        assert "healthy" not in states, (
            f"target unexpectedly went healthy in the wrong-VPC target group: {states}"
        )
        time.sleep(2)

    # positive control: the same task definition + subnets, load-balanced through a target group
    # in the SAME vpc as the service, does become healthy.
    service_name_ok = ctx.unique_name("sim2real-correctsvc-")
    ecs.create_service(
        cluster=cluster,
        serviceName=service_name_ok,
        taskDefinition=family,
        desiredCount=1,
        launchType="FARGATE",
        loadBalancers=[
            {
                "targetGroupArn": tg_correct_arn,
                "containerName": "app",
                "containerPort": 80,
            }
        ],
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": subnet_ids_a,
                "securityGroups": [task_sg_a],
                "assignPublicIp": "ENABLED",
            }
        },
    )
    ctx.on_cleanup(
        lambda: ecs.delete_service(cluster=cluster, service=service_name_ok, force=True)
    )

    healthy = _poll_until(
        lambda: [
            tid for tid, s in _target_states(ctx, tg_correct_arn) if s == "healthy"
        ],
        lambda v: len(v) == 1,
        timeout_s=300,
        interval_s=15,
    )
    assert len(healthy) == 1


# ===== helpers =====


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
    proc = _run_shell(
        ctx, ["aws", "--output", "json", *args], timeout_s=timeout_s, check=check
    )
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _shared_vpc_and_subnets(ctx, min_azs=2):
    """The run's shared network: its VPC and one public subnet in each of *min_azs* zones."""
    net = ctx.network()
    if len(net.subnet_ids) < min_azs:
        raise AssertionError(
            f"the shared network has fewer than {min_azs} AZ-distinct subnets: {net.subnet_ids}"
        )
    return net.vpc_id, net.subnet_ids[:min_azs]


def _create_isolated_vpc(
    ctx, cidr="10.90.0.0/16", subnet_cidrs=("10.90.1.0/24", "10.90.2.0/24")
):
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-wrongvpc-")
    vpc_id = ec2.create_vpc(
        CidrBlock=cidr,
        TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    azs = [
        a["ZoneName"] for a in ec2.describe_availability_zones()["AvailabilityZones"]
    ][:2]
    subnet_ids = []
    for cidr_block, az in zip(subnet_cidrs, azs):
        sid = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=cidr_block,
            AvailabilityZone=az,
            TagSpecifications=[
                {
                    "ResourceType": "subnet",
                    "Tags": [{"Key": "Name", "Value": f"{name}-{az}"}],
                }
            ],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=sid: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(sid)
    default_sg = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": ["default"]},
        ]
    )["SecurityGroups"][0]["GroupId"]
    return vpc_id, subnet_ids, default_sg


def _create_alb_and_task_sgs(ctx, vpc_id):
    ec2 = ctx.client("ec2")

    def _tags(name):
        return [
            {"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": name}]}
        ]

    alb_sg_name = ctx.unique_name("sim2real-albsg-")
    alb_sg = ec2.create_security_group(
        GroupName=alb_sg_name,
        Description="alb sg",
        VpcId=vpc_id,
        TagSpecifications=_tags(alb_sg_name),
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group_when_free(ec2, alb_sg))

    task_sg_name = ctx.unique_name("sim2real-tasksg-")
    task_sg = ec2.create_security_group(
        GroupName=task_sg_name,
        Description="task sg",
        VpcId=vpc_id,
        TagSpecifications=_tags(task_sg_name),
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group_when_free(ec2, task_sg))
    ec2.authorize_security_group_ingress(
        GroupId=task_sg,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 80,
                "ToPort": 80,
                "UserIdGroupPairs": [{"GroupId": alb_sg}],
            }
        ],
    )
    return alb_sg, task_sg


def _create_ecs_execution_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ecsexec-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    )
    # No unconditional wait here: the VPC/ALB provisioning that follows before either ECS service is
    # created already takes minutes, and the bounded `_running_count` poll (240s) absorbs any
    # remaining IAM role/policy propagation lag before ECS can assume this role to launch tasks.
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
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=task_def_arn))
    return family, task_def_arn


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
        state = elbv2.describe_load_balancers(LoadBalancerArns=[alb_arn])[
            "LoadBalancers"
        ][0]["State"]["Code"]
        if state == "active":
            return
        time.sleep(2)
    raise AssertionError(f"ALB {alb_arn} never became active, last state={state}")


def _target_states(ctx, tg_arn):
    elbv2 = ctx.client("elbv2")
    descs = elbv2.describe_target_health(TargetGroupArn=tg_arn)[
        "TargetHealthDescriptions"
    ]
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
            except ClientError as e:
                if e.response["Error"]["Code"] not in ("ServiceNotFoundException", "ServiceNotActiveException"):
                    raise
    while True:
        for task in arns("list_tasks", "taskArns", desiredStatus="RUNNING"):
            try:
                ecs.stop_task(cluster=cluster, task=task, reason="sim2real teardown")
            except ClientError as e:
                if e.response["Error"]["Code"] != "InvalidParameterException":  # already stopped
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
                    except ClientError as err:
                        if err.response["Error"]["Code"] != "ClusterNotFoundException":
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


# A load balancer, cluster or task in this VPC deletes asynchronously: its ENIs stay in the subnet /
# security group for a while, so DeleteSubnet / DeleteSecurityGroup / DeleteVpc fail with
# DependencyViolation until they leave. Wait (bounded) for the ENIs, retry DependencyViolation in the
# same window, and raise naming any ENI still attached; every other error propagates.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(10)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(10)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
