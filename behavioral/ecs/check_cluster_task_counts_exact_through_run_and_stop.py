"""cluster-task-counts-exact-through-run-and-stop."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cluster-task-counts-exact-through-run-and-stop"
GROUP = "task-lifecycle"
SERVICES = ["ecs"]


def _fargate_network(ctx):
    net = ctx.network()
    return list(net.subnet_ids), net.security_group_id


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _retire_task_definition(ecs, task_definition_arn: str) -> None:
    try:
        described = ecs.describe_task_definition(taskDefinition=task_definition_arn)["taskDefinition"]
    except ClientError as exc:
        if "Unable to describe task definition" in exc.response["Error"].get("Message", ""):
            return
        raise
    if described["status"] == "DELETE_IN_PROGRESS":
        return
    if described["status"] == "ACTIVE":
        ecs.deregister_task_definition(taskDefinition=task_definition_arn)
    failures = ecs.delete_task_definitions(taskDefinitions=[task_definition_arn]).get("failures", [])
    if failures:
        raise RuntimeError(f"task definition {task_definition_arn} teardown failed: {failures}")


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DescribeClusters' runningTasksCount/pendingTasksCount track a single Fargate task at exact
    settled states: 1/0 once DescribeTasks reads the long-lived task RUNNING, and 0/0 once an
    explicit StopTask is reflected by DescribeTasks reading STOPPED."""
    ecs = ctx.client("ecs")
    subnets, sg = _fargate_network(ctx)

    cluster_name = ctx.unique_name("sim2real-behav-ecs-lifecycle-cluster-")
    ecs.create_cluster(clusterName=cluster_name, tags=[{"key": "sim2real", "value": "true"}])
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_name))

    family = ctx.unique_name("sim2real-behav-ecs-lifecycle-td-")
    td = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        containerDefinitions=[
            {
                "name": "runner",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "essential": True,
                "command": ["sh", "-c", "sleep 3600"],
            }
        ],
        tags=[{"key": "sim2real", "value": "true"}],
    )["taskDefinition"]
    td_arn = td["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, td_arn))

    run_resp = ecs.run_task(
        cluster=cluster_name,
        taskDefinition=td_arn,
        launchType="FARGATE",
        count=1,
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": subnets,
                "securityGroups": [sg],
                "assignPublicIp": "ENABLED",
            }
        },
    )
    assert run_resp["failures"] == [], f"RunTask reported failures: {run_resp['failures']}"
    task_arn = run_resp["tasks"][0]["taskArn"]
    ctx.on_cleanup(lambda: ecs.stop_task(cluster=cluster_name, task=task_arn))

    def _describe_task():
        tasks = ecs.describe_tasks(cluster=cluster_name, tasks=[task_arn])["tasks"]
        return tasks[0] if tasks else None

    running = _poll_until(
        _describe_task, lambda t: t is not None and t["lastStatus"] == "RUNNING", timeout_s=180.0
    )
    assert running["lastStatus"] == "RUNNING", f"expected RUNNING, got {running['lastStatus']!r}"

    def _cluster():
        return ecs.describe_clusters(clusters=[cluster_name])["clusters"][0]

    settled_running = _poll_until(
        _cluster,
        lambda c: c["runningTasksCount"] == 1 and c["pendingTasksCount"] == 0,
        timeout_s=60.0,
    )
    assert settled_running["runningTasksCount"] == 1, (
        f"expected runningTasksCount == 1 while the long-lived task runs, "
        f"got {settled_running['runningTasksCount']}"
    )
    assert settled_running["pendingTasksCount"] == 0, (
        f"expected pendingTasksCount == 0 while the task is RUNNING, "
        f"got {settled_running['pendingTasksCount']}"
    )

    ecs.stop_task(cluster=cluster_name, task=task_arn)
    stopped = _poll_until(
        _describe_task, lambda t: t is not None and t["lastStatus"] == "STOPPED", timeout_s=180.0
    )
    assert stopped["lastStatus"] == "STOPPED", f"expected STOPPED, got {stopped['lastStatus']!r}"

    settled_stopped = _poll_until(
        _cluster,
        lambda c: c["runningTasksCount"] == 0 and c["pendingTasksCount"] == 0,
        timeout_s=120.0,
    )
    assert settled_stopped["runningTasksCount"] == 0, (
        f"expected runningTasksCount == 0 after StopTask settles to STOPPED, "
        f"got {settled_stopped['runningTasksCount']}"
    )
    assert settled_stopped["pendingTasksCount"] == 0, (
        f"expected pendingTasksCount == 0 after StopTask settles to STOPPED, "
        f"got {settled_stopped['pendingTasksCount']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
