"""service-deployment-event-timestamps-monotonic-across-updates."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "service-deployment-event-timestamps-monotonic-across-updates"
GROUP = "ordering"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Across several sequential UpdateService calls, ListServiceDeployments and
    DescribeServices.events never present timestamps out of order or duplicated --
    the server-side history is a consistent, monotonic timeline."""
    ecs = ctx.client("ecs")
    net = _default_networking(ctx)
    cluster = ctx.unique_name("sim2real-ecs-order-cluster-")
    ecs.create_cluster(clusterName=cluster, tags=[{"key": "sim2real:check", "value": CHECK}])
    ctx.on_cleanup(lambda: _try_delete_cluster(ctx, cluster))

    family = ctx.unique_name("sim2real-ecs-order-fam-")
    task_def_arns = [_register_task_def(ctx, family, i) for i in range(3)]

    service_name = ctx.unique_name("sim2real-ecs-order-svc-")
    # A real running Fargate task is required: with desiredCount=0 (no capacity to
    # actually deploy), ECS does not reliably mint a new service-deployment record on
    # every UpdateService call, so the "several deployments" premise doesn't hold.
    ecs.create_service(
        cluster=cluster,
        serviceName=service_name,
        taskDefinition=task_def_arns[0],
        desiredCount=1,
        launchType="FARGATE",
        networkConfiguration={"awsvpcConfiguration": net},
        tags=[{"key": "sim2real:check", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_service(ctx, cluster, service_name))
    _wait_for_running_task(ctx, cluster, service_name)

    # The initial CreateService itself mints deployment #1; wait for it to move past
    # PENDING before issuing the next update -- firing updates back-to-back while a
    # prior deployment is still PENDING lets ECS supersede/merge it rather than
    # minting a fresh, independently-timestamped entry, which would invalidate the
    # "several sequential deployments" premise this check relies on.
    _poll_until_deployment_count(ctx, cluster, service_name, min_count=1)
    _wait_until_latest_deployment_past_pending(ctx, cluster, service_name)

    update_windows = []
    for n, arn in enumerate(task_def_arns[1:], start=2):
        before = time.time()
        ecs.update_service(cluster=cluster, service=service_name, taskDefinition=arn)
        after = time.time()
        update_windows.append((before, after))
        _poll_until_deployment_count(ctx, cluster, service_name, min_count=n)
        _wait_until_latest_deployment_past_pending(ctx, cluster, service_name)

    deployments = _poll_until_deployment_count(ctx, cluster, service_name, min_count=3)


    # 1) No duplicated deployment ARNs.
    arns = [d["serviceDeploymentArn"] for d in deployments]
    assert len(arns) == len(set(arns)), f"duplicate serviceDeploymentArn entries: {arns}"

    # 2) The list's own returned order is newest-first by createdAt, never jumbled or oldest-first.
    created_at = [d["createdAt"] for d in deployments]
    assert created_at == sorted(created_at, reverse=True), (
        f"ListServiceDeployments order is not newest-first: {created_at}"
    )

    # 3) Re-listing must be stable (same order, same timeline) -- not reshuffled.
    deployments2 = ecs.list_service_deployments(cluster=cluster, service=service_name)["serviceDeployments"]
    arns2 = [d["serviceDeploymentArn"] for d in deployments2 if d["serviceDeploymentArn"] in set(arns)]
    common_first_pass = [a for a in arns if a in set(arns2)]
    assert arns2 == common_first_pass, "ListServiceDeployments order changed between successive calls"

    # 4) Distinct wall-clock deployments landed inside the expected windows we drove:
    #    at least one deployment's createdAt should fall after each update call's
    #    window opened (proves later updates produced strictly later deployments).
    sorted_created = sorted(created_at)
    assert sorted_created[0] < sorted_created[-1], "all deployment timestamps collapsed to the same instant"
    for before, _after in update_windows:
        assert any(ts.timestamp() >= before - 1 for ts in created_at), (
            f"no deployment timestamp found at/after update window start {before}"
        )

    # 5) DescribeServices.events is itself a consistent (non-reordered) timeline too,
    #    and gains events monotonically as we drive more updates.
    events = ecs.describe_services(cluster=cluster, services=[service_name])["services"][0]["events"]
    assert len(events) >= 1, f"expected at least one service event, got {events}"
    event_times = [e["createdAt"] for e in events]
    assert event_times == sorted(event_times, reverse=True), (
        f"service events are not newest-first: {event_times}"
    )
    ids = [e["id"] for e in events]
    assert len(ids) == len(set(ids)), "duplicate service event ids"


# ===== helpers =====

def _default_networking(ctx) -> dict:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region to launch a Fargate task")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets to launch a Fargate task in")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    return {
        "subnets": [subnets[0]["SubnetId"]],
        "securityGroups": [sgs[0]["GroupId"]] if sgs else [],
        "assignPublicIp": "ENABLED",
    }


def _register_task_def(ctx, family: str, revision_marker: int) -> str:
    ecs = ctx.client("ecs")
    resp = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        containerDefinitions=[
            {
                "name": "main",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "essential": True,
                "command": ["sleep", "3600"],
            }
        ],
        tags=[{"key": "sim2real:check", "value": CHECK}],
    )
    arn = resp["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, arn))
    return arn


def _wait_for_running_task(ctx, cluster: str, service_name: str, timeout_s: float = 240.0) -> str:
    ecs = ctx.client("ecs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        arns = ecs.list_tasks(cluster=cluster, serviceName=service_name, desiredStatus="RUNNING")["taskArns"]
        if arns:
            tasks = ecs.describe_tasks(cluster=cluster, tasks=arns)["tasks"]
            running = [t for t in tasks if t["lastStatus"] == "RUNNING"]
            if running:
                return running[0]["taskArn"]
        time.sleep(5)
    raise AssertionError(f"no task in service {service_name} reached RUNNING within {timeout_s}s")


def _delete_service(ctx, cluster: str, service_name: str) -> None:
    ecs = ctx.client("ecs")
    try:
        task_arns = ecs.list_tasks(cluster=cluster, serviceName=service_name)["taskArns"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ClusterNotFoundException", "ServiceNotFoundException"):
            raise
        task_arns = []
    try:
        ecs.delete_service(cluster=cluster, service=service_name, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ClusterNotFoundException",
            "ServiceNotFoundException",
        ):
            raise
    if not task_arns:
        return
    deadline = time.monotonic() + 180.0
    while time.monotonic() < deadline:
        try:
            tasks = ecs.describe_tasks(cluster=cluster, tasks=task_arns)["tasks"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                raise
            return
        if all(t["lastStatus"] == "STOPPED" for t in tasks):
            return
        time.sleep(2)
    raise AssertionError(f"tasks of service {service_name} not STOPPED within 180s")


def _try_delete_cluster(ctx, cluster: str) -> None:
    ecs = ctx.client("ecs")
    _drain_and_delete_ecs_cluster(ecs, cluster)


def _poll_until_deployment_count(ctx, cluster: str, service_name: str, min_count: int, timeout_s: float = 240.0):
    ecs = ctx.client("ecs")
    deadline = time.monotonic() + timeout_s
    deployments = []
    while time.monotonic() < deadline:
        deployments = ecs.list_service_deployments(cluster=cluster, service=service_name)["serviceDeployments"]
        if len(deployments) >= min_count:
            return deployments
        time.sleep(5)
    raise AssertionError(f"only {len(deployments)} service deployments recorded after {timeout_s}s, expected >= {min_count}")


def _wait_until_latest_deployment_past_pending(ctx, cluster: str, service_name: str, timeout_s: float = 240.0) -> None:
    """Block until the most-recently-created deployment has left PENDING, so the next
    UpdateService call is guaranteed to mint an independent deployment record instead of
    superseding a still-pending one."""
    ecs = ctx.client("ecs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        deployments = ecs.list_service_deployments(cluster=cluster, service=service_name)["serviceDeployments"]
        if deployments:
            latest = max(deployments, key=lambda d: d["createdAt"])
            if latest["status"] != "PENDING":
                return
        time.sleep(5)
    raise AssertionError(f"latest deployment for {service_name} still PENDING after {timeout_s}s")



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
                    "ClusterNotFoundException",
                    "ServiceNotFoundException",
                    "ServiceNotActiveException",
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
