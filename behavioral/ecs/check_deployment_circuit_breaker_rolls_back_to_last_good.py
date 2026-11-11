"""deployment-circuit-breaker-rolls-back-to-last-good."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "deployment-circuit-breaker-rolls-back-to-last-good"
GROUP = 'service-deployment'
SERVICES = ['ecs']

def _fargate_network(ctx):
    """(subnets, security group) for awsvpc tasks from the run's shared network."""
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


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """With the circuit breaker enabled, a crash-looping revision's deployment goes FAILED with a
    circuit-breaker reason and ECS rolls the service back to the last good task definition,
    leaving no running task of the bad revision."""
    ecs = ctx.client("ecs")
    cluster = ctx.unique_name("sim2real-behav-ecs-cluster-")
    ecs.create_cluster(clusterName=cluster)
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, cluster))

    family = ctx.unique_name("sim2real-behav-ecs-taskdef-fg-")

    def _register(command: list[str]) -> str:
        return ecs.register_task_definition(
            family=family,
            containerDefinitions=[
                {
                    "name": "app",
                    "image": "public.ecr.aws/docker/library/busybox:1.36",
                    "essential": True,
                    "command": command,
                }
            ],
            networkMode="awsvpc",
            requiresCompatibilities=["FARGATE"],
            cpu="256",
            memory="512",
        )["taskDefinition"]["taskDefinitionArn"]

    good_arn = _register(["sh", "-c", "sleep 3600"])
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[good_arn]))
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=good_arn))
    bad_arn = _register(["sh", "-c", "exit 1"])
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[bad_arn]))
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=bad_arn))
    assert good_arn != bad_arn, "the two revisions must be distinct"

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
        taskDefinition=good_arn,
        desiredCount=1,
        launchType="FARGATE",
        networkConfiguration=net_cfg,
        deploymentConfiguration={
            "deploymentCircuitBreaker": {"enable": True, "rollback": True},
            "maximumPercent": 200,
            "minimumHealthyPercent": 100,
        },
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

    breaker = created.get("deploymentConfiguration", {}).get("deploymentCircuitBreaker", {})
    assert breaker.get("enable") is True and breaker.get("rollback") is True, (
        f"the circuit-breaker configuration must round-trip, got {breaker}"
    )

    def _service() -> dict:
        return ecs.describe_services(cluster=cluster, services=[svc])["services"][0]

    def _primary(service: dict) -> dict:
        for dep in service.get("deployments", []):
            if dep.get("status") == "PRIMARY":
                return dep
        return {}

    _poll_until(
        _service,
        lambda s: s.get("runningCount") == 1 and _primary(s).get("rolloutState") == "COMPLETED",
        timeout_s=900,
        interval_s=15,
        description="the good revision converges to a COMPLETED rollout with 1 running task",
    )

    ecs.update_service(cluster=cluster, service=svc, taskDefinition=bad_arn)

    def _bad_deployment() -> dict:
        for dep in _service().get("deployments", []):
            if dep.get("taskDefinition") == bad_arn:
                return dep
        return {}

    # The breaker trips only after several failed task launches, hence the long budget.
    failed = _poll_until(
        _bad_deployment,
        lambda d: d.get("rolloutState") == "FAILED",
        timeout_s=1500,
        interval_s=20,
        description="ECS's own circuit breaker drives the crash-looping deployment to rolloutState FAILED",
    )
    reason = (failed.get("rolloutStateReason") or "").lower()
    assert "circuit breaker" in reason, (
        "a breaker-tripped rollout must attribute the failure to the circuit breaker, got "
        f"rolloutStateReason={failed.get('rolloutStateReason')!r}"
    )

    settled = _poll_until(
        _service,
        lambda s: _primary(s).get("taskDefinition") == good_arn
        and _primary(s).get("rolloutState") == "COMPLETED"
        and s.get("runningCount") == 1,
        timeout_s=1200,
        interval_s=20,
        description="ECS autonomously rolls the service back to the last known-good task definition",
    )
    assert _primary(settled).get("taskDefinition") == good_arn, (
        f"after rollback the PRIMARY deployment must reference {good_arn}, got {_primary(settled)}"
    )

    running = ecs.list_tasks(cluster=cluster, serviceName=svc, desiredStatus="RUNNING")["taskArns"]
    assert running, "the rolled-back service must still be running a task"
    for task in ecs.describe_tasks(cluster=cluster, tasks=running)["tasks"]:
        assert task["taskDefinitionArn"] == good_arn, (
            "no task of the rejected revision may survive the rollback, got "
            f"{task['taskArn']} on {task['taskDefinitionArn']}"
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

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
