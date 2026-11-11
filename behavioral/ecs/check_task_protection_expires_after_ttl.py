"""task-protection-expires-after-ttl."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "task-protection-expires-after-ttl"
GROUP = "visibility-timeout-ttl"
SERVICES = ["ecs"]


_ECS_TAGS = [{"key": "sim2real", "value": "true"}]


# timing:real-time — ttl: 60 s https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_UpdateTaskProtection.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:representation", "plane:control", "timing:real-time")
def run(ctx) -> None:
    """UpdateTaskProtection with a short expiresInMinutes automatically reverts to
    unprotected after the TTL elapses, as observed via GetTaskProtection. The task is
    launched via a service, since task protection requires service membership."""
    ecs = ctx.client("ecs")
    subnet_id = _default_subnet(ctx)
    if subnet_id is None:
        raise AssertionError("no shared network VPC/subnet available to launch a real Fargate task")

    cluster_name = ctx.unique_name("sim2real-behav-cl-")
    cluster_arn = ecs.create_cluster(clusterName=cluster_name, tags=_ECS_TAGS)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _safe_delete_cluster(ctx, cluster_arn))

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
                "essential": True,
                "command": ["sleep", "900"],
            }
        ],
        tags=_ECS_TAGS,
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))

    service_name = ctx.unique_name("sim2real-behav-svc-")
    service_arn = ecs.create_service(
        cluster=cluster_arn,
        serviceName=service_name,
        taskDefinition=task_def_arn,
        desiredCount=1,
        launchType="FARGATE",
        networkConfiguration={
            "awsvpcConfiguration": {"subnets": [subnet_id], "assignPublicIp": "ENABLED"}
        },
        tags=_ECS_TAGS,
    )["service"]["serviceArn"]
    ctx.on_cleanup(lambda: _safe_delete_service(ctx, cluster_arn, service_arn))

    def _list_task_arns() -> list[str]:
        return ecs.list_tasks(cluster=cluster_arn, serviceName=service_arn)["taskArns"]

    task_arns = _poll_until(_list_task_arns, lambda a: len(a) >= 1, timeout_s=60.0, interval_s=3.0)
    task_arn = task_arns[0]
    ctx.on_cleanup(lambda: _safe_stop_task(ctx, cluster_arn, task_arn))

    def _task_status() -> str:
        return ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])["tasks"][0]["lastStatus"]

    try:
        _poll_until(_task_status, lambda s: s == "RUNNING", timeout_s=180.0, interval_s=5.0)
    except AssertionError:
        raise AssertionError(
            "task never reached RUNNING (likely no network egress in this test environment)",
        )

    before = time.time()
    ecs.update_task_protection(
        cluster=cluster_arn, tasks=[task_arn], protectionEnabled=True, expiresInMinutes=1
    )

    def _protection() -> dict[str, Any]:
        resp = ecs.get_task_protection(cluster=cluster_arn, tasks=[task_arn])
        assert not resp.get("failures"), f"GetTaskProtection failures: {resp['failures']}"
        return resp["protectedTasks"][0]

    initial = _protection()
    assert initial["protectionEnabled"] is True, "task protection was not enabled"
    assert "expirationDate" in initial, "protected task is missing an expirationDate"
    expiration = initial["expirationDate"]
    expiration_epoch = expiration.timestamp() if hasattr(expiration, "timestamp") else float(expiration)
    assert 0 < (expiration_epoch - before) <= 150, (
        f"expected a ~60s expiration window for expiresInMinutes=1, got {expiration_epoch - before}s"
    )

    # Poll well past the 1-minute TTL for the automatic revert to unprotected.
    reverted = _poll_until(
        _protection, lambda p: p["protectionEnabled"] is False, timeout_s=180.0, interval_s=10.0
    )
    assert reverted["protectionEnabled"] is False, "task protection did not expire after its TTL"


def _default_subnet(ctx) -> str | None:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        return None
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        return None
    return subnets[0]["SubnetId"]


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last}")


def _safe_stop_task(ctx, cluster_arn: str, task_arn: str) -> None:
    ecs = ctx.client("ecs")
    try:
        ecs.stop_task(cluster=cluster_arn, task=task_arn, reason="behavioral-check-cleanup")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ClusterNotFoundException":
            raise


def _safe_delete_service(ctx, cluster_arn: str, service_arn: str) -> None:
    ecs = ctx.client("ecs")
    try:
        ecs.update_service(cluster=cluster_arn, service=service_arn, desiredCount=0)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ClusterNotFoundException",
            "NamespaceNotFoundException",
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


def _safe_delete_cluster(ctx, cluster_arn: str) -> None:
    ecs = ctx.client("ecs")
    _drain_and_delete_ecs_cluster(ecs, cluster_arn)


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
