"""run-task-lifecycle-transitions."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "run-task-lifecycle-transitions"
GROUP = "state"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """RunTask on Fargate drives a task through PROVISIONING/PENDING -> RUNNING, and
    StopTask drives it to STOPPED with stopCode=UserInitiated."""
    ecs = ctx.client("ecs")
    cluster_arn = _create_cluster(ctx)
    net = _default_network(ctx)
    td = _register_sleep_task_def(ctx)

    task_arn, task = _run_task_and_wait_running(ecs, cluster_arn, td["taskDefinitionArn"], net)
    ctx.on_cleanup(lambda: _stop_task_ignore(ecs, cluster_arn, task_arn))

    assert task["lastStatus"] == "RUNNING", f"task never reached RUNNING: {task['lastStatus']}"
    assert task["desiredStatus"] == "RUNNING", f"expected desiredStatus RUNNING, got {task['desiredStatus']}"
    assert task["taskDefinitionArn"] == td["taskDefinitionArn"], (
        f"expected taskDefinitionArn {td['taskDefinitionArn']}, got {task['taskDefinitionArn']}"
    )
    assert task["clusterArn"] == cluster_arn, f"expected clusterArn {cluster_arn}, got {task['clusterArn']}"
    assert task.get("containers"), "expected container entries on a RUNNING task"
    assert task["containers"][0]["lastStatus"] == "RUNNING", (
        f"expected container lastStatus RUNNING, got {task['containers'][0]['lastStatus']}"
    )

    ecs.stop_task(cluster=cluster_arn, task=task_arn, reason="sim2real-behav-stop")
    stopped = _poll_until(
        lambda: ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])["tasks"][0],
        lambda t: t["lastStatus"] == "STOPPED",
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert stopped["desiredStatus"] == "STOPPED", f"expected desiredStatus STOPPED, got {stopped['desiredStatus']}"
    assert stopped["stopCode"] == "UserInitiated", f"expected UserInitiated stopCode, got {stopped.get('stopCode')}"
    assert "stoppedAt" in stopped and stopped["stoppedAt"] is not None, (
        f"expected a populated stoppedAt, got {stopped.get('stoppedAt')!r}"
    )


# ===== helpers =====
from botocore.exceptions import ClientError


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _default_network(ctx):
    """Adopt the run's shared network if it has one; otherwise create a minimal
    routable VPC of our own, so the check does not depend on an ambient shared network
    that a freshly provisioned account may not have."""
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        vpc_id = vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        sgs = ec2.describe_security_groups(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
        )["SecurityGroups"]
        if subnets and sgs:
            return {"subnet_id": subnets[0]["SubnetId"], "sg_id": sgs[0]["GroupId"]}
    return _create_network(ctx)


def _tag_spec(resource_type: str) -> list:
    return [{"ResourceType": resource_type, "Tags": [{"Key": "sim2real", "Value": CHECK}]}]


def _create_network(ctx):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.90.0.0/24", TagSpecifications=_tag_spec("vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _safe_delete_vpc(ec2, vpc_id))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.90.0.0/25", TagSpecifications=_tag_spec("subnet")
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _safe_delete_subnet(ec2, subnet_id))
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})

    igw_id = ec2.create_internet_gateway(TagSpecifications=_tag_spec("internet-gateway"))[
        "InternetGateway"
    ]["InternetGatewayId"]
    ctx.on_cleanup(lambda: _safe_delete_igw(ec2, igw_id, vpc_id))
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

    rt_id = ec2.describe_route_tables(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "association.main", "Values": ["true"]}]
    )["RouteTables"][0]["RouteTableId"]
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)

    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("expected an auto-created default security group on the new VPC")
    return {"subnet_id": subnet_id, "sg_id": sgs[0]["GroupId"]}


def _safe_delete_vpc(ec2, vpc_id: str) -> None:
    try:
        _delete_net(ec2, "delete_vpc", VpcId=vpc_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidVpcID.NotFound":
            raise


def _safe_delete_subnet(ec2, subnet_id: str) -> None:
    try:
        _delete_net(ec2, "delete_subnet", SubnetId=subnet_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidSubnetID.NotFound":
            raise


def _safe_delete_igw(ec2, igw_id: str, vpc_id: str) -> None:
    try:
        _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("Gateway.NotAttached", "InvalidInternetGatewayID.NotFound"):
            raise
    try:
        _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidInternetGatewayID.NotFound":
            raise


def _create_cluster(ctx):
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-behav-cluster-")
    arn = ecs.create_cluster(clusterName=name, tags=[{"key": "sim2real", "value": CHECK}])["cluster"][
        "clusterArn"
    ]
    ctx.on_cleanup(lambda: _safe_delete_cluster(ecs, arn))
    return arn


def _safe_delete_cluster(ecs, arn: str) -> None:
    _drain_and_delete_ecs_cluster(ecs, arn)


def _register_sleep_task_def(ctx, family_prefix="sim2real-behav-sleep"):
    ecs = ctx.client("ecs")
    family = ctx.unique_name(f"{family_prefix}-")
    td = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        containerDefinitions=[
            {
                "name": "main",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "command": ["sleep", "900"],
                "essential": True,
            }
        ],
        tags=[{"key": "sim2real", "value": CHECK}],
    )["taskDefinition"]

    def _cleanup():
        try:
            ecs.deregister_task_definition(taskDefinition=td["taskDefinitionArn"])
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and any(f in err.get("Message", "") for f in ("Unable to describe task definition", "in the process of being deleted"))
            ):
                raise
        ecs.delete_task_definitions(taskDefinitions=[td["taskDefinitionArn"]])

    ctx.on_cleanup(_cleanup)
    return td


def _run_task_and_wait_running(ecs, cluster_arn, task_def_arn, net, **kwargs):
    resp = ecs.run_task(
        cluster=cluster_arn,
        taskDefinition=task_def_arn,
        launchType=kwargs.pop("launchType", "FARGATE"),
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": [net["subnet_id"]],
                "securityGroups": [net["sg_id"]],
                "assignPublicIp": "ENABLED",
            }
        },
        **kwargs,
    )
    if resp.get("failures"):
        raise AssertionError(f"RunTask failures: {resp['failures']}")
    task_arn = resp["tasks"][0]["taskArn"]
    task = _poll_until(
        lambda: ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])["tasks"][0],
        lambda t: t["lastStatus"] in ("RUNNING", "STOPPED"),
        timeout_s=240.0,
        interval_s=6.0,
    )
    return task_arn, task


def _stop_task_ignore(ecs, cluster_arn: str, task_arn: str) -> None:
    try:
        ecs.stop_task(cluster=cluster_arn, task=task_arn, reason="sim2real-behav-cleanup")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ClusterNotFoundException":
            raise


# EC2 network teardown: an asynchronously deleted resource's ENIs stay in the subnet / security group
# after its delete returns, so DeleteSubnet / DeleteSecurityGroup / DeleteVpc fail with DependencyViolation.
# Wait (bounded, shared by all of one check's network deletes) for the ENIs to go, then raise naming them.
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
        _time.sleep(2)
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
        _time.sleep(2)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]



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

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
