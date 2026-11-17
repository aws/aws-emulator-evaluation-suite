"""service-desired-count-zero-emits-no-task-started-event."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "service-desired-count-zero-emits-no-task-started-event"
GROUP = "events"
SERVICES = ["ecs"]


@tags("axis:negative-delivery", "cap:c4", "plane:data", "dp:api")
def run(ctx) -> None:
    """A service created with desiredCount 0 starts no task: once raised to desiredCount 1, its
    events hold exactly one task-started event, naming the one task it then launched."""
    ecs = ctx.client("ecs")
    net = ctx.network()

    cluster_name = ctx.unique_name("sim2real-behav-cl-")
    cluster_arn = ecs.create_cluster(clusterName=cluster_name)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _drain_and_delete_cluster(ecs, cluster_arn))

    family = ctx.unique_name("sim2real-behav-td-")
    task_def_arn = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        containerDefinitions=[
            {
                "name": "c",
                "image": "public.ecr.aws/docker/library/alpine:3.20",
                "command": ["sleep", "900"],
                "essential": True,
            }
        ],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))

    net_cfg = {
        "awsvpcConfiguration": {
            "subnets": [net.subnet_ids[0]],
            "securityGroups": [net.security_group_id],
            "assignPublicIp": "ENABLED",
        }
    }

    service_name = ctx.unique_name("sim2real-behav-svc-")
    service_arn = ecs.create_service(
        cluster=cluster_arn,
        serviceName=service_name,
        taskDefinition=task_def_arn,
        desiredCount=0,
        launchType="FARGATE",
        networkConfiguration=net_cfg,
    )["service"]["serviceArn"]
    ctx.on_cleanup(lambda: _safe_delete_service(ecs, cluster_arn, service_arn))

    # The idle service settles first: it reports a steady state at desiredCount 0.
    steady = f"(service {service_name}) has reached a steady state."
    _poll_until(
        lambda: _service_event_messages(ecs, cluster_arn, service_arn),
        lambda msgs: steady in msgs,
        timeout_s=_budget_s(ctx, 300.0),
        interval_s=5.0,
    )

    ecs.update_service(cluster=cluster_arn, service=service_arn, desiredCount=1)
    task_arn = _poll_until(
        lambda: _running_task_arn(ecs, cluster_arn, service_name),
        lambda v: v is not None,
        timeout_s=_budget_s(ctx, 300.0),
        interval_s=5.0,
    )
    task_id = task_arn.rsplit("/", 1)[-1]
    expected_message = f"(service {service_name}) has started 1 tasks: (task {task_id})."

    messages = _poll_until(
        lambda: _service_event_messages(ecs, cluster_arn, service_arn),
        lambda msgs: expected_message in msgs,
        timeout_s=_budget_s(ctx, 120.0),
        interval_s=5.0,
    )
    # Every event the service emitted while at desiredCount 0 is still listed: the one
    # task-started event is the one for the task the raise launched.
    started = [m for m in messages if f"(service {service_name}) has started " in m]
    assert started == [expected_message], (
        f"expected exactly the task-started event {expected_message!r}, got {started!r} "
        f"among {messages!r}"
    )


# ===== helpers =====
def _budget_s(ctx, cap_s: float) -> float:
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last}")


def _running_task_arn(ecs, cluster_arn: str, service_name: str):
    arns = ecs.list_tasks(cluster=cluster_arn, serviceName=service_name)["taskArns"]
    if not arns:
        return None
    tasks = ecs.describe_tasks(cluster=cluster_arn, tasks=arns)["tasks"]
    for t in tasks:
        if t["lastStatus"] == "RUNNING":
            return t["taskArn"]
    return None


def _service_event_messages(ecs, cluster_arn: str, service_arn: str) -> list[str]:
    svc = ecs.describe_services(cluster=cluster_arn, services=[service_arn])["services"][0]
    return [e["message"] for e in svc.get("events", [])]


def _safe_delete_service(ecs, cluster_arn: str, service_arn: str) -> None:
    try:
        ecs.update_service(cluster=cluster_arn, service=service_arn, desiredCount=0)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ClusterNotFoundException",
            "ServiceNotActiveException",
            "ServiceNotFoundException",
        ):
            raise
    try:
        ecs.delete_service(cluster=cluster_arn, service=service_arn, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ClusterNotFoundException",
            "ServiceNotFoundException",
        ):
            raise


def _drain_and_delete_cluster(ecs, cluster: str, timeout_s: float = 900.0, interval_s: float = 10.0) -> None:
    """Stop the cluster's tasks, wait for them to stop, then delete it.

    DeleteCluster is refused while tasks remain, and a task's ENI stays in the shared
    network until it has stopped, which would keep the network from being deleted.
    """
    deadline = time.monotonic() + timeout_s

    def arns(op: str, key: str, **kw):
        return [a for page in ecs.get_paginator(op).paginate(cluster=cluster, **kw) for a in page.get(key, [])]

    try:
        running = arns("list_tasks", "taskArns", desiredStatus="RUNNING")
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ClusterNotFoundException":
            return
        raise
    for task in running:
        try:
            ecs.stop_task(cluster=cluster, task=task, reason="sim2real teardown")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                raise
    while True:
        stopping = arns("list_tasks", "taskArns", desiredStatus="STOPPED")
        live = []
        for i in range(0, len(stopping), 100):
            batch = stopping[i : i + 100]
            live += [t for t in ecs.describe_tasks(cluster=cluster, tasks=batch)["tasks"] if t["lastStatus"] != "STOPPED"]
        if not live and not arns("list_tasks", "taskArns", desiredStatus="RUNNING"):
            break
        if time.monotonic() >= deadline:
            raise AssertionError(f"{len(live)} task(s) in {cluster} still not STOPPED after {timeout_s:.0f}s")
        time.sleep(interval_s)
    while True:
        try:
            ecs.delete_cluster(cluster=cluster)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ClusterNotFoundException":
                return
            if code not in ("ClusterContainsTasksException", "ClusterContainsServicesException", "UpdateInProgressException"):
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _retire_task_definition(ecs, task_definition: str) -> None:
    """Deregister a task definition revision, then delete it: a deregistered revision stays
    INACTIVE until DeleteTaskDefinitions removes it. An already-deleted revision is fine."""
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
