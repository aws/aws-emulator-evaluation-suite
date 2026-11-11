"""service-converges-running-count-to-desired."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "service-converges-running-count-to-desired"
GROUP = 'service-steady-state'
SERVICES = ['ecs']

# ===== helpers =====


def _fargate_network(ctx):
    """(subnets, security group) for Fargate (awsvpc) tasks from the run's shared network (ctx.network), the
    same on every target; the run owns and deletes the network."""
    net = ctx.network()
    return list(net.subnet_ids), net.security_group_id


def _poll_until(fn, pred, *, timeout_s=60, interval_s=3, description=""):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = fn()
        if pred(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description!r} (last={last!r})")


def _error_code(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return None


# ===== end helpers =====


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A service's runningCount converges to desiredCount 2 with RUNNING, CONNECTED tasks and a COMPLETED
    deployment; scaling to 1 re-converges and stops one task with stopCode ServiceSchedulerInitiated,
    proving the scheduler owns placement in both directions."""
    ecs = ctx.client("ecs")
    cluster = ctx.unique_name("sim2real-behav-ecs-cluster-")
    ecs.create_cluster(clusterName=cluster)
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, cluster))

    family = ctx.unique_name("sim2real-behav-ecs-taskdef-fg-")
    td_arn = ecs.register_task_definition(
        family=family,
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "essential": True,
                "command": ["sh", "-c", "sleep 3600"],
            }
        ],
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[td_arn]))
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=td_arn))

    subnets, sg = _fargate_network(ctx)
    net_cfg = {
        "awsvpcConfiguration": {
            "subnets": subnets[:1],
            "securityGroups": [sg],
            "assignPublicIp": "ENABLED",
        }
    }

    svc = ctx.unique_name("sim2real-behav-ecs-svc-")
    created = ecs.create_service(
        cluster=cluster,
        serviceName=svc,
        taskDefinition=td_arn,
        desiredCount=2,
        launchType="FARGATE",
        networkConfiguration=net_cfg,
    )["service"]

    def _drain_and_delete_service():
        try:
            ecs.update_service(cluster=cluster, service=svc, desiredCount=0)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "ClusterNotFoundException",
                "NamespaceNotFoundException",
                "ServiceNotActiveException",
                "ServiceNotFoundException",
            ):
                raise
        try:
            ecs.delete_service(cluster=cluster, service=svc, force=True)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "ClusterNotFoundException",
                "ServiceNotFoundException",
            ):
                raise
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            found = ecs.describe_services(cluster=cluster, services=[svc]).get("services") or [{}]
            if found[0].get("status", "INACTIVE") == "INACTIVE":
                return
            time.sleep(10)

    ctx.on_cleanup(_drain_and_delete_service)

    assert created["status"] == "ACTIVE", created["status"]
    assert created["desiredCount"] == 2, created["desiredCount"]

    def _service() -> dict:
        return ecs.describe_services(cluster=cluster, services=[svc])["services"][0]

    def _primary(service: dict) -> dict:
        for dep in service.get("deployments", []):
            if dep.get("status") == "PRIMARY":
                return dep
        return {}

    converged = _poll_until(
        _service,
        lambda s: s.get("runningCount") == 2
        and _primary(s).get("rolloutState") == "COMPLETED",
        timeout_s=900,
        interval_s=15,
        description="the service scheduler places 2 RUNNING tasks and the primary deployment completes",
    )
    primary = _primary(converged)
    assert primary.get("runningCount") == 2, (
        f"primary deployment must count 2 running tasks, got {primary}"
    )
    assert primary.get("desiredCount") == 2, primary.get("desiredCount")
    assert primary.get("pendingCount") == 0, (
        f"a COMPLETED rollout must have no pending tasks left, got {primary}"
    )
    assert primary.get("taskDefinition") == td_arn, primary.get("taskDefinition")

    running_arns = ecs.list_tasks(
        cluster=cluster, serviceName=svc, desiredStatus="RUNNING"
    )["taskArns"]
    assert len(running_arns) == 2, (
        f"expected exactly 2 tasks owned by the service, got {running_arns}"
    )
    described = ecs.describe_tasks(cluster=cluster, tasks=running_arns)["tasks"]
    for task in described:
        assert task["lastStatus"] == "RUNNING", (
            f"a task counted in runningCount must actually be RUNNING, got "
            f"{task['taskArn']}={task['lastStatus']} (stoppedReason={task.get('stoppedReason')})"
        )
        assert task.get("startedAt") is not None, (
            f"a RUNNING task must carry startedAt, got {task.get('startedAt')!r} for {task['taskArn']}"
        )
        assert task.get("connectivity") == "CONNECTED", (
            f"a RUNNING awsvpc task must report connectivity CONNECTED, got {task.get('connectivity')!r}"
        )
        assert task.get("group") == f"service:{svc}", (
            f"the task must be attributed to the service group, got {task.get('group')!r}"
        )

    # Scale in: the scheduler must converge DOWN too, and own the stop decision.
    ecs.update_service(cluster=cluster, service=svc, desiredCount=1)
    scaled = _poll_until(
        _service,
        lambda s: s.get("runningCount") == 1 and s.get("pendingCount") == 0,
        timeout_s=600,
        interval_s=15,
        description="the service scheduler converges runningCount down to the new desiredCount of 1",
    )
    assert scaled.get("desiredCount") == 1, scaled.get("desiredCount")

    stopped_arns = [a for a in running_arns if a not in
                    ecs.list_tasks(cluster=cluster, serviceName=svc, desiredStatus="RUNNING")["taskArns"]]
    assert len(stopped_arns) == 1, (
        f"exactly one of the two original tasks must have been stopped, got {stopped_arns}"
    )
    victim = _poll_until(
        lambda: ecs.describe_tasks(cluster=cluster, tasks=stopped_arns)["tasks"][0],
        lambda t: t["lastStatus"] == "STOPPED",
        timeout_s=420,
        interval_s=10,
        description="the scaled-in task reaches STOPPED",
    )
    assert victim.get("stopCode") == "ServiceSchedulerInitiated", (
        "a scale-in stop must be attributed to the service scheduler, got "
        f"stopCode={victim.get('stopCode')!r} stoppedReason={victim.get('stoppedReason')!r}"
    )
    assert victim.get("stoppedReason"), f"stoppedReason must be populated, got {victim!r}"


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
