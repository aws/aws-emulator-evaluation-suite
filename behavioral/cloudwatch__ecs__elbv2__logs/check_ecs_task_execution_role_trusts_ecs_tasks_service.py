"""ecs-task-execution-role-trusts-ecs-tasks-service."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ecs-task-execution-role-trusts-ecs-tasks-service"
GROUP = "iam-trust"
SERVICES = ["cloudwatch", "ecs", "elbv2", "logs"]

_IMAGE = "public.ecr.aws/docker/library/busybox:latest"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """The task execution role's trust policy names ecs-tasks.amazonaws.com, and a Fargate task
    launched with that role runs its container to normal completion, so the trust works end to end."""
    net = _create_network(ctx)
    role = _create_execution_role(ctx, "trust", attach_execution_policy=True)

    # 1. The trust document itself must name ecs-tasks.amazonaws.com as principal.
    iam = ctx.client("iam")
    doc = iam.get_role(RoleName=role["name"])["Role"]["AssumeRolePolicyDocument"]
    statements = doc["Statement"]
    assert len(statements) == 1, f"expected exactly one trust statement, got {statements}"
    stmt = statements[0]
    assert stmt["Effect"] == "Allow", f"expected Effect=Allow, got {stmt['Effect']!r}"
    assert stmt["Action"] == "sts:AssumeRole", f"expected Action=sts:AssumeRole, got {stmt['Action']!r}"
    principal = stmt["Principal"]["Service"]
    if isinstance(principal, str):
        principal = [principal]
    assert "ecs-tasks.amazonaws.com" in principal, f"expected ecs-tasks.amazonaws.com in principal, got {principal}"

    # 2. Prove the trust actually works: a Fargate task using this execution role
    # must be able to start its container and run to a normal completion. If ECS
    # cannot assume the role, the task stops early with a ResourceInitializationError
    # instead of ever running the container to exit(0).
    cluster = _create_cluster(ctx)
    log_group = _create_log_group(ctx, "trust")
    task_def_arn = _register_task_def(
        ctx,
        "trust",
        containers=[
            _container_def(ctx, "app", _IMAGE, ["sh", "-c", "echo hello-from-trust-task; sleep 2"], log_group, "app")
        ],
        execution_role_arn=role["arn"],
    )
    task = _run_task_until_role_ready(ctx, cluster, task_def_arn, net)

    assert task["lastStatus"] == "STOPPED", f"expected lastStatus=STOPPED, got {task['lastStatus']!r} (task={task})"
    assert task.get("stoppedReason") == "Essential container in task exited", (
        f"expected stoppedReason='Essential container in task exited', got {task.get('stoppedReason')!r} "
        f"(stopCode={task.get('stopCode')!r}) -- a role that ECS cannot assume stops the task early instead"
    )
    containers = task["containers"]
    assert len(containers) == 1, f"expected exactly one container, got {containers}"
    assert containers[0]["exitCode"] == 0, f"expected exitCode=0, got {containers[0].get('exitCode')!r}"


# ===== helpers =====

def _create_network(ctx) -> dict:
    """A dedicated VPC is provisioned so the task does not depend on the
    account's default VPC configuration (a default VPC with a missing DHCP
    option set makes every Fargate task fail at launch regardless of the
    execution role's trust policy). A freshly created VPC auto-associates a
    valid DHCP option set. The VPC has a public subnet +
    internet gateway + default route so the task can pull its public image, and
    torn down by one cleanup that waits out the Fargate ENI-detachment lag
    before deleting the subnet."""
    ec2 = ctx.client("ec2")
    net_tags = [{"Key": "sim2real", "Value": CHECK}]

    vpc_id = ec2.create_vpc(
        CidrBlock="10.199.0.0/24", TagSpecifications=[{"ResourceType": "vpc", "Tags": net_tags}]
    )["Vpc"]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.199.0.0/25",
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": net_tags}],
    )["Subnet"]["SubnetId"]
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": net_tags}]
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

    rt_id = ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["RouteTables"][0][
        "RouteTableId"
    ]
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)

    sg_id = next(
        sg["GroupId"]
        for sg in ec2.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["SecurityGroups"]
        if sg["GroupName"] == "default"
    )

    def _teardown_network():
        deadline = time.monotonic() + 540
        # Fargate ENIs linger for a bit after tasks stop; wait them out (the
        # task's own cleanup, registered later, runs first under LIFO and has
        # already initiated the stop) so the subnet is deletable.
        while time.monotonic() < deadline:
            enis = ec2.describe_network_interfaces(Filters=[{"Name": "subnet-id", "Values": [subnet_id]}]).get(
                "NetworkInterfaces", []
            )
            if not enis:
                break
            time.sleep(10)

        def _delete(call, gone_codes):
            # Return on the resource's not-found codes; retry DependencyViolation while the
            # released ENIs and public addresses drain, and raise everything else.
            while True:
                try:
                    call()
                    return
                except ClientError as exc:
                    code = exc.response.get("Error", {}).get("Code")
                    if code in gone_codes:
                        return
                    if code != "DependencyViolation" or time.monotonic() >= deadline:
                        raise
                    time.sleep(10)

        _delete(lambda: ec2.delete_subnet(SubnetId=subnet_id), ("InvalidSubnetID.NotFound",))
        _delete(
            lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id),
            ("Gateway.NotAttached", "InvalidInternetGatewayID.NotFound"),
        )
        _delete(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id), ("InvalidInternetGatewayID.NotFound",))
        _delete(lambda: ec2.delete_vpc(VpcId=vpc_id), ("InvalidVpcID.NotFound",))

    ctx.on_cleanup(_teardown_network)
    return {"subnets": [subnet_id], "security_groups": [sg_id]}


def _create_execution_role(ctx, suffix: str, attach_execution_policy: bool) -> dict:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"sim2real-ecsexec-{suffix}-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ecs-tasks.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    if attach_execution_policy:
        policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return {"name": role_name, "arn": role_arn}


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_cluster(ctx) -> str:
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-ecscluster-")
    ecs.create_cluster(clusterName=name, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=name))
    return name


def _create_log_group(ctx, suffix: str, retention_days: int | None = None) -> str:
    logs = ctx.client("logs")
    name = f"/ecs/{ctx.unique_name(f'sim2real-lg-{suffix}-')}"
    logs.create_log_group(logGroupName=name, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=name))
    if retention_days is not None:
        logs.put_retention_policy(logGroupName=name, retentionInDays=retention_days)
    return name


def _container_def(ctx, name: str, image: str, command: list, log_group: str, stream_prefix: str) -> dict:
    return {
        "name": name,
        "image": image,
        "essential": True,
        "command": command,
        "logConfiguration": {
            "logDriver": "awslogs",
            "options": {
                "awslogs-group": log_group,
                "awslogs-region": ctx.region,
                "awslogs-stream-prefix": stream_prefix,
            },
        },
    }


def _register_task_def(ctx, family_suffix: str, containers: list, execution_role_arn: str) -> str:
    ecs = ctx.client("ecs")
    family = ctx.unique_name(f"sim2real-taskdef-{family_suffix}-")
    resp = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        executionRoleArn=execution_role_arn,
        containerDefinitions=containers,
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    task_def_arn = resp["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))
    return task_def_arn


def _run_task(ctx, cluster: str, task_def_arn: str, net: dict) -> str:
    ecs = ctx.client("ecs")
    last_failures = None
    for _ in range(6):
        resp = ecs.run_task(
            cluster=cluster,
            taskDefinition=task_def_arn,
            launchType="FARGATE",
            count=1,
            networkConfiguration={
                "awsvpcConfiguration": {
                    "subnets": net["subnets"],
                    "securityGroups": net["security_groups"],
                    "assignPublicIp": "ENABLED",
                }
            },
        )
        if resp.get("tasks"):
            return resp["tasks"][0]["taskArn"]
        last_failures = resp.get("failures")
        time.sleep(5)
    raise AssertionError(f"run_task never scheduled a task; failures={last_failures}")


def _run_task_until_role_ready(
    ctx, cluster: str, task_def_arn: str, net: dict, deadline_s: float = 220.0, retry_sleep_s: float = 10.0
) -> dict:
    """Right after attaching the trust policy, IAM's write may not yet have
    propagated to the ECS control plane. That surfaces two ways: RunTask itself
    synchronously raises ClientException ("ECS was unable to assume the
    role..."), or RunTask accepts the task and it stops almost immediately with
    stopCode=TaskFailedToStart instead of ever running the container. Retry
    through both forms, bounded by a deadline, until the role is demonstrably
    assumable (the container actually runs) or the deadline is exhausted."""
    deadline = time.monotonic() + deadline_s
    last_task: dict | None = None
    while True:
        try:
            task_arn = _run_task(ctx, cluster, task_def_arn, net)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClientException" or "assume" not in str(exc).lower():
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(retry_sleep_s)
            continue
        remaining = max(30.0, deadline - time.monotonic())
        last_task = _wait_for_task_stopped(ctx, cluster, task_arn, timeout_s=remaining)
        if last_task.get("stopCode") != "TaskFailedToStart" or time.monotonic() >= deadline:
            return last_task
        time.sleep(retry_sleep_s)


def _wait_for_task_stopped(ctx, cluster: str, task_arn: str, timeout_s: float = 300.0, interval_s: float = 6.0) -> dict:
    ecs = ctx.client("ecs")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = ecs.describe_tasks(cluster=cluster, tasks=[task_arn])
        tasks = resp.get("tasks", [])
        if tasks:
            last = tasks[0]
            if last["lastStatus"] == "STOPPED":
                return last
        time.sleep(interval_s)
    raise AssertionError(f"task did not reach STOPPED within {timeout_s}s; last={last}")


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
