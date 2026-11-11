"""run-task-large-environment-override-payload-round-trip."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "run-task-large-environment-override-payload-round-trip"
GROUP = "representation"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A containerOverrides environment payload near the 8192-character limit is echoed back
    unchanged, in order, by both RunTask and a later DescribeTasks."""
    ecs = ctx.client("ecs")

    net = ctx.network()

    cluster_arn = ecs.create_cluster(clusterName=ctx.unique_name("sim2real-ecs-rto-"))[
        "cluster"
    ]["clusterArn"]
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, cluster_arn))

    task_def_arn = ecs.register_task_definition(
        family=ctx.unique_name("sim2real-ecs-rto-td-"),
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "command": ["sh", "-c", "sleep 15"],
                "essential": True,
            }
        ],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))

    env_pairs = [{"name": f"OVR_VAR_{i}", "value": f"payload-{i}-" + ("x" * 950)} for i in range(8)]
    overrides = {"containerOverrides": [{"name": "app", "environment": env_pairs}]}

    run_resp = ecs.run_task(
        cluster=cluster_arn,
        taskDefinition=task_def_arn,
        launchType="FARGATE",
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": [net.subnet_ids[0]],
                "securityGroups": [net.security_group_id],
                "assignPublicIp": "ENABLED",
            }
        },
        overrides=overrides,
        count=1,
    )
    assert not run_resp.get("failures"), f"RunTask failures: {run_resp.get('failures')}"
    task_arn = run_resp["tasks"][0]["taskArn"]
    ctx.on_cleanup(lambda: ecs.stop_task(cluster=cluster_arn, task=task_arn))

    run_env = run_resp["tasks"][0]["overrides"]["containerOverrides"][0]["environment"]
    assert _env_matches(run_env, env_pairs), (
        f"RunTask response must echo the large environment override unchanged, "
        f"expected {env_pairs} got {run_env}"
    )

    described = ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])
    assert not described.get("failures"), f"DescribeTasks failures: {described.get('failures')}"
    described_env = described["tasks"][0]["overrides"]["containerOverrides"][0]["environment"]
    assert _env_matches(described_env, env_pairs), (
        f"DescribeTasks must independently echo the same large environment override, "
        f"expected {env_pairs} got {described_env}"
    )

    _wait_task_stopped(ctx, cluster_arn, task_arn, timeout_s=220.0)


# ===== helpers =====
def _env_matches(actual: list, expected: list) -> bool:
    actual_by_name = {e["name"]: e["value"] for e in actual}
    expected_by_name = {e["name"]: e["value"] for e in expected}
    return actual_by_name == expected_by_name


def _wait_task_stopped(ctx, cluster_arn: str, task_arn: str, timeout_s: float = 220.0) -> None:
    ecs = ctx.client("ecs")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        resp = ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])
        tasks = resp.get("tasks", [])
        if tasks:
            last_status = tasks[0]["lastStatus"]
            if last_status == "STOPPED":
                return
        time.sleep(3.0)
    raise AssertionError(
        f"task {task_arn} did not reach STOPPED within {timeout_s}s, last lastStatus={last_status!r}"
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
