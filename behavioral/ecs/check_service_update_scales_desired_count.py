"""service-update-scales-desired-count."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "service-update-scales-desired-count"
GROUP = "state"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateService desiredCount 1->2 drives runningCount to converge on the new target."""
    ecs = ctx.client("ecs")
    cluster_arn = _create_cluster(ctx)
    subnets, sg_id = _fargate_network(ctx)
    td = _register_sleep_task_def(ctx)

    svc_name = ctx.unique_name("sim2real-behav-svc-")
    net_cfg = {
        "awsvpcConfiguration": {
            "subnets": subnets[:1],
            "securityGroups": [sg_id],
            "assignPublicIp": "ENABLED",
        }
    }
    svc = ecs.create_service(
        cluster=cluster_arn,
        serviceName=svc_name,
        taskDefinition=td["taskDefinitionArn"],
        desiredCount=1,
        launchType="FARGATE",
        networkConfiguration=net_cfg,
    )["service"]
    svc_arn = svc["serviceArn"]
    ctx.on_cleanup(lambda: _cleanup_service(ecs, cluster_arn, svc_arn))

    _poll_until(
        lambda: ecs.describe_services(cluster=cluster_arn, services=[svc_arn])["services"][0],
        lambda s: s["runningCount"] == 1 and s["pendingCount"] == 0,
        timeout_s=300.0,
        interval_s=8.0,
    )

    updated = ecs.update_service(cluster=cluster_arn, service=svc_arn, desiredCount=2)["service"]
    assert updated["desiredCount"] == 2, f"expected desiredCount=2 immediately after update, got {updated['desiredCount']}"

    scaled = _poll_until(
        lambda: ecs.describe_services(cluster=cluster_arn, services=[svc_arn])["services"][0],
        lambda s: s["runningCount"] == 2 and s["pendingCount"] == 0,
        timeout_s=300.0,
        interval_s=8.0,
    )
    assert scaled["runningCount"] == 2, f"expected runningCount=2 after scale-up, got {scaled['runningCount']}"


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _fargate_network(ctx):
    """(subnets, security group) for Fargate (awsvpc) tasks from the run's shared network (ctx.network), the
    same on every target; the run owns and deletes the network."""
    net = ctx.network()
    return list(net.subnet_ids), net.security_group_id


def _create_cluster(ctx):
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-behav-cluster-")
    arn = ecs.create_cluster(clusterName=name)["cluster"]["clusterArn"]
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


def _cleanup_service(ecs, cluster_arn: str, svc_arn: str) -> None:
    try:
        ecs.update_service(cluster=cluster_arn, service=svc_arn, desiredCount=0)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ClusterNotFoundException",
            "NamespaceNotFoundException",
            "ServiceNotActiveException",
            "ServiceNotFoundException",
        ):
            raise
    try:
        ecs.delete_service(cluster=cluster_arn, service=svc_arn, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ClusterNotFoundException",
            "ServiceNotFoundException",
        ):
            raise


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
            except ClientError:
                pass
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
