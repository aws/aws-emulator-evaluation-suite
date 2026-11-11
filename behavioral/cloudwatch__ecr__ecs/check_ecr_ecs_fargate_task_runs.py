"""ecr-ecs-fargate-task-runs."""

from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "ecr-ecs-fargate-task-runs"

GROUP = "container-lifecycle"

SERVICES = ["cloudwatch", "ecr", "ecs"]

PUBLIC_IMAGE = "public.ecr.aws/docker/library/busybox:latest"
_CLUSTER_BUSY = ("ClusterContainsTasksException", "ClusterContainsServicesException",
                 "UpdateInProgressException")


# Each create_* registers its teardown via ctx.on_cleanup; LIFO order stops the task before
# the task def, cluster and repository are removed.
def _awsvpc_config(network: dict) -> dict:
    return {
        "awsvpcConfiguration": {
            "subnets": network["subnet_ids"],
            "securityGroups": [network["sg_id"]],
            "assignPublicIp": "ENABLED",  # the subnets route 0.0.0.0/0 to an IGW to pull the image
        }
    }


def _ensure_ecs_service_linked_role(ctx) -> None:
    """Create the ECS service-linked role idempotently: RunTask (unlike CreateService) does not
    auto-create it, and fails with "Unable to assume the service linked role" without it."""
    try:
        ctx.client("iam").create_service_linked_role(AWSServiceName="ecs.amazonaws.com")
    except Exception as e:  # noqa: BLE001 - already-exists is success
        msg = str(e).lower()
        if (
            "has been taken" not in msg
            and "already" not in msg
            and "invalidinput" not in msg
        ):
            pass  # non-exists errors: let the subsequent RunTask surface the real problem


def _create_repo(ctx, **kwargs) -> dict:
    name = ctx.unique_name("sim2real-xsvc-ecr-repo-")
    ecr = ctx.client("ecr")
    resp = ecr.create_repository(
        repositoryName=name,
        tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-xsvc"},
        ],
        **kwargs,
    )
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))
    return resp["repository"]


def _create_cluster(ctx) -> dict:
    name = ctx.unique_name("sim2real-xsvc-ecs-cluster-")
    ecs = ctx.client("ecs")
    resp = ecs.create_cluster(
        clusterName=name,
        tags=[
            {"key": "sim2real:managed", "value": "true"},
            {"key": "sim2real:prefix", "value": "sim2real-xsvc"},
        ],
    )

    def _cleanup() -> None:
        # A stopping task can still block cluster delete briefly: retry exactly that, then raise.
        from botocore.exceptions import ClientError

        deadline = time.monotonic() + 60
        while True:
            try:
                ecs.delete_cluster(cluster=name)
                return
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code == "ClusterNotFoundException":
                    return
                if code not in _CLUSTER_BUSY or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

    ctx.on_cleanup(_cleanup)
    return resp["cluster"]


def _register_fargate_task_def(ctx, container_defs, execution_role_arn=None) -> dict:
    family = ctx.unique_name("sim2real-xsvc-ecs-taskdef-fg-")
    ecs = ctx.client("ecs")
    kwargs: dict = dict(
        family=family,
        containerDefinitions=container_defs,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        tags=[
            {"key": "sim2real:managed", "value": "true"},
            {"key": "sim2real:prefix", "value": "sim2real-xsvc"},
        ],
    )
    if execution_role_arn:
        kwargs["executionRoleArn"] = execution_role_arn
    td = ecs.register_task_definition(**kwargs)["taskDefinition"]
    td_arn = td["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, td_arn))
    return td


def _run_fargate_task(ctx, cluster: str, task_def_arn: str, network: dict) -> dict:
    _ensure_ecs_service_linked_role(ctx)
    ecs = ctx.client("ecs")
    resp = ecs.run_task(
        cluster=cluster,
        taskDefinition=task_def_arn,
        launchType="FARGATE",
        networkConfiguration=_awsvpc_config(network),
    )
    for t in resp.get("tasks", []):
        ctx.on_cleanup(lambda a=t["taskArn"]: ecs.stop_task(cluster=cluster, task=a))
    return resp


def _await_task_running(
    ctx, cluster: str, task_arn: str, timeout_s: float = 420
) -> dict:
    """Poll DescribeTasks until the task is RUNNING; a STOPPED task fails with its stoppedReason."""
    ecs = ctx.client("ecs")

    def probe() -> dict:
        tasks = ecs.describe_tasks(cluster=cluster, tasks=[task_arn]).get("tasks", [])
        return tasks[0] if tasks else {}

    task = _poll_until(
        probe,
        lambda t: t.get("lastStatus") in ("RUNNING", "STOPPED"),
        timeout_s=timeout_s,
        interval_s=5,
        description=f"task {task_arn} RUNNING",
    )
    assert task.get("lastStatus") == "RUNNING", (
        f"task did not reach RUNNING: lastStatus={task.get('lastStatus')} "
        f"stoppedReason={task.get('stoppedReason')}"
    )
    return task


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """An ECR repository supports create, describe and lifecycle policy, and an ECS Fargate task
    started with RunTask reaches RUNNING (a public image, so no docker push is needed)."""
    ecr = ctx.client("ecr")

    repo = _create_repo(ctx)
    repo_name = repo["repositoryName"]
    assert repo["repositoryUri"].endswith("/" + repo_name), repo["repositoryUri"]

    described = ecr.describe_repositories(repositoryNames=[repo_name])["repositories"]
    assert len(described) == 1, f"expected 1 repository, got {described}"
    assert described[0]["repositoryArn"] == repo["repositoryArn"], (
        f"expected repositoryArn {repo['repositoryArn']!r}, "
        f"got {described[0]['repositoryArn']!r}"
    )

    lifecycle = (
        '{"rules":[{"rulePriority":1,"description":"expire untagged",'
        '"selection":{"tagStatus":"untagged","countType":"imageCountMoreThan","countNumber":5},'
        '"action":{"type":"expire"}}]}'
    )
    ecr.put_lifecycle_policy(repositoryName=repo_name, lifecyclePolicyText=lifecycle)
    got = ecr.get_lifecycle_policy(repositoryName=repo_name)
    assert got["lifecyclePolicyText"] == lifecycle, (
        f"expected lifecyclePolicyText {lifecycle!r}, got {got['lifecyclePolicyText']!r}"
    )

    network = _create_network(ctx)
    cluster = _create_cluster(ctx)
    container_defs = [
        {
            "name": "app",
            "image": PUBLIC_IMAGE,
            "essential": True,
            "command": ["sh", "-c", "echo container-started; sleep 3600"],
        }
    ]
    td = _register_fargate_task_def(ctx, container_defs)

    resp = _run_fargate_task(ctx, cluster["clusterName"], td["taskDefinitionArn"], network)
    assert not resp.get("failures"), f"RunTask failures: {resp.get('failures')}"
    tasks = resp.get("tasks", [])
    assert len(tasks) == 1, f"expected 1 task, got {tasks}"
    task_arn = tasks[0]["taskArn"]
    assert tasks[0]["desiredStatus"] == "RUNNING", tasks[0]["desiredStatus"]

    task = _await_task_running(ctx, cluster["clusterName"], task_arn, timeout_s=300)
    assert task["taskDefinitionArn"] == td["taskDefinitionArn"], (
        f"expected taskDefinitionArn {td['taskDefinitionArn']!r}, "
        f"got {task['taskDefinitionArn']!r}"
    )


def _tag_spec(ctx, resource_type: str, kind: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{kind}-")}]}


def _create_network(ctx) -> dict:
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.99.0.0/16", TagSpecifications=[_tag_spec(ctx, "vpc", "vpc")])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[_tag_spec(ctx, "internet-gateway", "igw")]
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id))
    ctx.on_cleanup(lambda: _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id))

    azs = [az["ZoneName"] for az in ec2.describe_availability_zones()["AvailabilityZones"][:2]]
    subnet_ids = []
    for i, az in enumerate(azs):
        sid = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.99.{i}.0/24", AvailabilityZone=az,
            TagSpecifications=[_tag_spec(ctx, "subnet", f"subnet{i}")],
        )["Subnet"]["SubnetId"]
        ec2.modify_subnet_attribute(SubnetId=sid, MapPublicIpOnLaunch={"Value": True})
        ctx.on_cleanup(lambda sid=sid: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(sid)

    rt_id = ec2.create_route_table(
        VpcId=vpc_id, TagSpecifications=[_tag_spec(ctx, "route-table", "rt")]
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_route_table", RouteTableId=rt_id))
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    for sid in subnet_ids:
        assoc_id = ec2.associate_route_table(RouteTableId=rt_id, SubnetId=sid)["AssociationId"]
        ctx.on_cleanup(lambda assoc_id=assoc_id: ec2.disassociate_route_table(AssociationId=assoc_id))

    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-sg-"), Description="sim2real ecs fargate task sg", VpcId=vpc_id,
        TagSpecifications=[_tag_spec(ctx, "security-group", "sg")],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids, "sg_id": sg_id}


# EC2 network teardown waits (bounded) for AWS-managed ENIs to leave before it deletes: a stopped
# Fargate task releases its ENI asynchronously, so an immediate DeleteSubnet / DeleteSecurityGroup /
# DeleteVpc fails with DependencyViolation. DependencyViolation is retried inside one shared window
# that fits the 900s cleanup budget, and a final failure raises.
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



def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


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
