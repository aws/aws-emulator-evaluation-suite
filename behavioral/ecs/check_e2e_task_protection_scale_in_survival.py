"""e2e-task-protection-scale-in-survival."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-task-protection-scale-in-survival"
GROUP = "e2e"
SERVICES = ["ecs"]


# timing:real-time — ttl: 60 s https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_UpdateTaskProtection.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx: Any) -> None:
    """A task with scale-in protection survives a forced scale-in while its unprotected
    siblings are stopped; once protection expires, the same task is no longer immune.
    """
    ecs = ctx.client("ecs")
    subnets, sg_id = _fargate_network(ctx)

    cluster_name = ctx.unique_name("sim2real-ecs-prot-")
    cluster_arn = ecs.create_cluster(
        clusterName=cluster_name,
        tags=[{"key": "sim2real:managed", "value": "true"}],
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster_when_empty(ecs, cluster_arn))

    family = ctx.unique_name("sim2real-ecs-prot-td-")
    task_def_arn = _register_sleep_task_def(ctx, family)
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))

    service_name = ctx.unique_name("sim2real-ecs-prot-svc-")
    _ensure_ecs_service_linked_role(ctx)
    _call_with_slr_retry(
        lambda: ecs.create_service(
            cluster=cluster_arn,
            serviceName=service_name,
            taskDefinition=task_def_arn,
            desiredCount=3,
            launchType="FARGATE",
            networkConfiguration={
                "awsvpcConfiguration": {
                    "subnets": subnets,
                    "securityGroups": [sg_id],
                    "assignPublicIp": "ENABLED",
                }
            },
            tags=[{"key": "sim2real:managed", "value": "true"}],
        )
    )
    ctx.on_cleanup(
        lambda: _ignore(lambda: ecs.delete_service(cluster=cluster_arn, service=service_name, force=True))
    )

    def _describe_service() -> dict:
        return ecs.describe_services(cluster=cluster_arn, services=[service_name])["services"][0]

    _poll_until(
        _describe_service,
        lambda s: s["runningCount"] == 3 and s["pendingCount"] == 0,
        timeout_s=480.0,
        interval_s=10.0,
    )

    original_task_arns = ecs.list_tasks(cluster=cluster_arn, serviceName=service_name)["taskArns"]
    assert len(original_task_arns) == 3
    protected_arn = original_task_arns[0]
    unprotected_arns = original_task_arns[1:]

    protect_resp = ecs.update_task_protection(
        cluster=cluster_arn, tasks=[protected_arn], protectionEnabled=True, expiresInMinutes=1
    )
    assert protect_resp["failures"] == []
    assert protect_resp["protectedTasks"][0]["protectionEnabled"] is True

    # Force a scale-in that must remove 2 of the 3 tasks.
    ecs.update_service(cluster=cluster_arn, service=service_name, desiredCount=1)

    _poll_until(
        _describe_service,
        lambda s: s["runningCount"] == 1 and s["desiredCount"] == 1,
        timeout_s=300.0,
        interval_s=10.0,
    )

    statuses = ecs.describe_tasks(cluster=cluster_arn, tasks=original_task_arns)["tasks"]
    by_arn = {t["taskArn"]: t["lastStatus"] for t in statuses}
    assert by_arn[protected_arn] == "RUNNING", "protected task must survive the scale-in"

    # The service-level runningCount can reach its target slightly before the stopped
    # siblings finish their STOPPING transition; poll each unprotected task to its terminal
    # STOPPED state rather than asserting on a single snapshot.
    def _unprotected_statuses() -> dict:
        tasks = ecs.describe_tasks(cluster=cluster_arn, tasks=unprotected_arns)["tasks"]
        return {t["taskArn"]: t["lastStatus"] for t in tasks}

    final_unprotected = _poll_until(
        _unprotected_statuses,
        lambda statuses: all(status == "STOPPED" for status in statuses.values()),
        timeout_s=180.0,
        interval_s=10.0,
    )
    for arn in unprotected_arns:
        assert final_unprotected[arn] == "STOPPED", "unprotected task must be stopped by the scale-in"
    # Re-affirm the protected task is still untouched after its siblings fully drained.
    assert ecs.describe_tasks(cluster=cluster_arn, tasks=[protected_arn])["tasks"][0]["lastStatus"] == "RUNNING"


    # Wait for the documented protection window (min 1 minute) to actually lapse, then
    # confirm via GetTaskProtection rather than assuming.
    def _protection_state() -> bool:
        resp = ecs.get_task_protection(cluster=cluster_arn, tasks=[protected_arn])
        return resp["protectedTasks"][0]["protectionEnabled"]

    _poll_until(
        _protection_state,
        lambda enabled: enabled is False,
        timeout_s=150.0,
        interval_s=5.0,
    )

    # Now that protection lapsed, a further scale-in must be able to remove the same task.
    ecs.update_service(cluster=cluster_arn, service=service_name, desiredCount=0)

    _poll_until(
        _describe_service,
        lambda s: s["runningCount"] == 0 and s["desiredCount"] == 0,
        timeout_s=180.0,
        interval_s=5.0,
    )
    final_status = _poll_until(
        lambda: ecs.describe_tasks(cluster=cluster_arn, tasks=[protected_arn])["tasks"][0]["lastStatus"],
        lambda status: status == "STOPPED",
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert final_status == "STOPPED"


def _ignore(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ClusterNotFoundException",
            "ServiceNotFoundException",
        ):
            raise


def _delete_cluster_when_empty(ecs, cluster_arn, *, timeout_s=180.0, interval_s=10.0) -> None:
    """DeleteCluster rejects with ClusterContainsServicesException while the just-deleted
    service is still draining, since force=True makes DeleteService return before the
    service (and its ENIs) are actually gone. Retry rather than swallow, or the cluster
    (and the still-not-fully-drained service under it) leaks."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            _drain_and_delete_ecs_cluster(ecs, cluster_arn)
            return
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code == "ClusterNotFoundException":
                return
            if code != "ClusterContainsServicesException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _poll_until(probe, predicate, *, timeout_s=300.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _register_sleep_task_def(ctx, family, command=None, log_group=None, execution_role_arn=None):
    ecs = ctx.client("ecs")
    container = {
        "name": "app",
        "image": "public.ecr.aws/docker/library/busybox:1.36",
        "command": command or ["sleep", "1800"],
        "essential": True,
    }
    if log_group:
        container["logConfiguration"] = {
            "logDriver": "awslogs",
            "options": {
                "awslogs-group": log_group,
                "awslogs-region": ctx.region,
                "awslogs-stream-prefix": "sim2real",
            },
        }
    kwargs: dict = dict(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        containerDefinitions=[container],
        tags=[{"key": "sim2real:managed", "value": "true"}],
    )
    if execution_role_arn:
        kwargs["executionRoleArn"] = execution_role_arn
    resp = ecs.register_task_definition(**kwargs)
    return resp["taskDefinition"]["taskDefinitionArn"]


def _ensure_ecs_service_linked_role(ctx) -> None:
    """Proactively create AWSServiceRoleForECS so CreateService/PutClusterCapacityProviders
    don't race the just-in-time SLR creation on a fresh account (fresh accounts otherwise see
    'Unable to assume the service linked role' on the first ever ECS service call). Propagation
    is bounded by _call_with_slr_retry's own retry loop, not by a sleep here."""
    iam = ctx.client("iam")
    try:
        iam.create_service_linked_role(AWSServiceName="ecs.amazonaws.com")
    except Exception:
        pass


def _call_with_slr_retry(fn, *, timeout_s=90.0, interval_s=5.0):
    """Retry an ECS call that can transiently fail with InvalidParameterException
    ('Unable to assume the service linked role...') while AWSServiceRoleForECS propagates."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as e:
            msg = e.response.get("Error", {}).get("Message", "")
            if "service linked role" not in msg.lower() or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _fargate_network(ctx):
    """(subnets, security group) for Fargate (awsvpc) tasks from the run's shared network (ctx.network), the
    same on every target; the run owns and deletes the network."""
    net = ctx.network()
    return list(net.subnet_ids[:2]), net.security_group_id


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
