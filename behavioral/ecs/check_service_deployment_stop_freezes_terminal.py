"""service-deployment-stop-freezes-terminal."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "service-deployment-stop-freezes-terminal"
GROUP = 'service-deployment'
SERVICES = ['ecs']


FARGATE_CONTAINER_DEFS = [
    {
        "name": "app",
        "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
        "essential": True,
        "command": ["sleep", "600"],
    }
]

_STOP_STATUSES = ("STOPPED", "STOP_REQUESTED", "ROLLBACK_SUCCESSFUL", "ROLLBACK_IN_PROGRESS")
_TERMINAL_STATUSES = ("STOPPED", "ROLLBACK_SUCCESSFUL", "ROLLBACK_FAILED")


def _poll_until(fn, pred, *, timeout_s, interval_s=5):
    deadline = time.monotonic() + timeout_s
    while True:
        val = fn()
        if pred(val):
            return val
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last={val!r})")
        time.sleep(interval_s)


def _fargate_network(ctx):
    """(subnets, security group) for Fargate (awsvpc) tasks from the run's shared network (ctx.network), the
    same on every target; the run owns and deletes the network."""
    net = ctx.network()
    return list(net.subnet_ids), net.security_group_id


def _delete_cluster_retrying(ecs, name, *, timeout_s=120, interval_s=5):
    """DeleteCluster right after ``delete_service(force=True)`` routinely hits
    ClusterContainsServicesException -- the forced service delete is async and the
    service is still DRAINING when LIFO cleanup order reaches the cluster. A cleanup
    that raises is swallowed by the runner (best-effort teardown), so a single
    attempt here means a permanently leaked cluster; retry until the drain clears."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            _drain_and_delete_ecs_cluster(ecs, name)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ClusterNotFoundException":
                return
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _register_fargate_td(ctx, ecs):
    td = ecs.register_task_definition(
        family=ctx.unique_name("sim2real-behav-ecs-taskdef-fg-"),
        containerDefinitions=FARGATE_CONTAINER_DEFS,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
    )["taskDefinition"]
    arn = td["taskDefinitionArn"]
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[arn]))
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=arn))
    return arn


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Stopping an IN_PROGRESS service deployment freezes it in a terminal STOPPED/ROLLBACK
    state that never resumes; re-stopping it is a no-op or a rejection, never a resurrection.
    """
    ecs = ctx.client("ecs")
    subnets, sg = _fargate_network(ctx)
    net_cfg = {
        "awsvpcConfiguration": {"subnets": subnets[:1], "securityGroups": [sg], "assignPublicIp": "ENABLED"}
    }

    cluster = ecs.create_cluster(clusterName=ctx.unique_name("sim2real-behav-ecs-cluster-"))["cluster"]
    name = cluster["clusterName"]
    ctx.on_cleanup(lambda: _delete_cluster_retrying(ecs, name))
    td1_arn = _register_fargate_td(ctx, ecs)
    td2_arn = _register_fargate_td(ctx, ecs)

    svc_name = ctx.unique_name("bg-svc-")
    ecs.create_service(
        cluster=name,
        serviceName=svc_name,
        taskDefinition=td1_arn,
        desiredCount=1,
        launchType="FARGATE",
        networkConfiguration=net_cfg,
        deploymentConfiguration={"strategy": "BLUE_GREEN"},
    )
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=name, service=svc_name, force=True))

    # Let the initial deployment settle so we cleanly isolate the SECOND one.
    _poll_until(
        lambda: ecs.list_service_deployments(cluster=name, service=svc_name)["serviceDeployments"],
        lambda deployments: any(d["status"] in ("SUCCESSFUL", "STOPPED") for d in deployments),
        timeout_s=180,
    )

    ecs.update_service(cluster=name, service=svc_name, taskDefinition=td2_arn)

    def _find_new_deployment():
        deployments = ecs.list_service_deployments(cluster=name, service=svc_name)["serviceDeployments"]
        in_progress = [d for d in deployments if d["status"] == "IN_PROGRESS"]
        return in_progress[0] if in_progress else None

    new_dep = _poll_until(_find_new_deployment, lambda d: d is not None, timeout_s=60, interval_s=3)
    deployment_arn = new_dep["serviceDeploymentArn"]

    ecs.stop_service_deployment(serviceDeploymentArn=deployment_arn, stopType="ROLLBACK")

    def _describe() -> dict:
        return ecs.describe_service_deployments(serviceDeploymentArns=[deployment_arn])[
            "serviceDeployments"
        ][0]

    stopped = _poll_until(_describe, lambda d: d["status"] in _STOP_STATUSES, timeout_s=120, interval_s=3)
    assert stopped["status"] in _STOP_STATUSES, f"unexpected status right after stopping: {stopped['status']}"

    final = _poll_until(_describe, lambda d: d["status"] in _TERMINAL_STATUSES, timeout_s=180)
    assert final["status"] in _TERMINAL_STATUSES, (
        f"expected a terminal stop/rollback status, got {final['status']}"
    )

    frozen_status = final["status"]
    observed: list[str] = []

    def _record_status() -> list[str]:
        observed.append(_describe()["status"])
        return observed

    _poll_until(
        _record_status,
        lambda obs: len(obs) >= 3 and all(s == frozen_status for s in obs),
        timeout_s=30,
    )
    assert all(s == frozen_status for s in observed), (
        f"expected every repeated poll to observe the same frozen status {frozen_status}, got {observed}"
    )

    # A deployment reached via an explicit prior stop (this one) is idempotent on a second
    # StopServiceDeployment call -- like StopTask against an already-stopped task, it does not
    # raise. This check's deployment took the explicit-stop path, so idempotent success is the only
    # correct answer here, not a hedge across both.)
    ecs.stop_service_deployment(serviceDeploymentArn=deployment_arn, stopType="ROLLBACK")
    unchanged = _describe()
    assert unchanged["status"] == frozen_status, (
        f"re-stopping must not change the status away from {frozen_status}, got {unchanged['status']}"
    )


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

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
