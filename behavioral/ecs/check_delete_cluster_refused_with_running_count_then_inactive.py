"""delete-cluster-refused-with-running-count-then-inactive."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-cluster-refused-with-running-count-then-inactive"
GROUP = "cluster-lifecycle"
SERVICES = ["ecs"]

_REFUSED = ("ClusterContainsTasksException", "The Cluster cannot be deleted while Tasks are active.")

_CONTAINER_DEFS = [
    {
        "name": "app",
        "image": "public.ecr.aws/docker/library/busybox:1.36",
        "essential": True,
        "command": ["sh", "-c", "sleep 600"],
    }
]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:negative-classes", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """DeleteCluster on an ACTIVE cluster with one RUNNING task is refused with
    ClusterContainsTasksException, and DescribeClusters reads ACTIVE with runningTasksCount 1;
    once the task is STOPPED, DeleteCluster returns INACTIVE and DescribeClusters agrees."""
    ecs = ctx.client("ecs")
    net = ctx.network()
    name = ctx.unique_name("sim2real-behav-ecs-cluster-")
    ecs.create_cluster(clusterName=name, tags=[{"key": "sim2real", "value": "true"}])
    ctx.on_cleanup(lambda: _drain_and_delete(ecs, name))

    td = ecs.register_task_definition(
        family=ctx.unique_name("sim2real-behav-ecs-taskdef-"),
        containerDefinitions=_CONTAINER_DEFS,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
    )["taskDefinition"]
    ctx.on_cleanup(lambda a=td["taskDefinitionArn"]: ecs.delete_task_definitions(taskDefinitions=[a]))
    ctx.on_cleanup(lambda a=td["taskDefinitionArn"]: ecs.deregister_task_definition(taskDefinition=a))

    resp = ecs.run_task(
        cluster=name,
        taskDefinition=td["taskDefinitionArn"],
        launchType="FARGATE",
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": list(net.subnet_ids),
                "securityGroups": [net.security_group_id],
                "assignPublicIp": "ENABLED",
            }
        },
    )
    assert not resp.get("failures"), f"unexpected RunTask failures: {resp['failures']!r}"
    tasks = resp.get("tasks", [])
    assert len(tasks) == 1, f"expected exactly one task from RunTask, got {len(tasks)}"
    task_arn = tasks[0]["taskArn"]
    ctx.on_cleanup(lambda: _safe_stop_task(ecs, name, task_arn))

    # Setup confirmation: the task must actually reach RUNNING before the refusal below means
    # anything, else a target that never schedules the task would pass it vacuously.
    running_status = _poll(
        lambda: _task_status(ecs, name, task_arn), lambda s: s in ("RUNNING", "STOPPED"), 180.0,
    )
    assert running_status == "RUNNING", (
        f"expected the task to reach RUNNING before the blocked delete, got {running_status!r}"
    )

    code, message = _error(lambda: ecs.delete_cluster(cluster=name))
    assert (code, message) == _REFUSED, (
        f"expected {_REFUSED!r} while a task is running, got {(code, message)!r}"
    )

    refused = ecs.describe_clusters(clusters=[name])["clusters"][0]
    assert refused["status"] == "ACTIVE", (
        f"cluster should stay ACTIVE after the refused delete, got {refused['status']!r}"
    )
    assert refused["runningTasksCount"] == 1, (
        f"expected runningTasksCount == 1 on the cluster the refused delete left untouched, "
        f"got {refused['runningTasksCount']!r}"
    )

    ecs.stop_task(cluster=name, task=task_arn, reason="sim2real check teardown")
    stopped_status = _poll(lambda: _task_status(ecs, name, task_arn), lambda s: s == "STOPPED", 180.0)
    assert stopped_status == "STOPPED", f"task did not settle STOPPED in time: {stopped_status!r}"

    deleted = ecs.delete_cluster(cluster=name)["cluster"]
    assert deleted["status"] == "INACTIVE", (
        f"expected DeleteCluster to return INACTIVE once the blocking task settled STOPPED, "
        f"got {deleted['status']!r}"
    )

    final = ecs.describe_clusters(clusters=[name])["clusters"]
    assert len(final) == 1, f"expected the deleted cluster still visible via an independent read, got {final!r}"
    assert final[0]["status"] == "INACTIVE", (
        f"independent DescribeClusters read expected INACTIVE, got {final[0]['status']!r}"
    )


# ===== helpers =====

def _task_status(ecs, cluster: str, task_arn: str) -> str:
    rows = ecs.describe_tasks(cluster=cluster, tasks=[task_arn])["tasks"]
    return rows[0]["lastStatus"] if rows else "MISSING"


def _poll(probe, predicate, timeout_s: float, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last!r}")


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore (code, message). A call that succeeds raises instead."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


def _safe_stop_task(ecs, cluster: str, task_arn: str) -> None:
    try:
        ecs.stop_task(cluster=cluster, task=task_arn, reason="sim2real cleanup")
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ClusterNotFoundException", "InvalidParameterException"):
            raise


def _drain_and_delete(ecs, cluster: str, timeout_s: float = 300.0, interval_s: float = 5.0) -> None:
    """Stop every RUNNING task on ``cluster``, wait for it to settle, then delete the cluster."""
    deadline = time.monotonic() + timeout_s
    try:
        running = ecs.list_tasks(cluster=cluster, desiredStatus="RUNNING")["taskArns"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ClusterNotFoundException":
            return
        raise
    for task_arn in running:
        _safe_stop_task(ecs, cluster, task_arn)
    while True:
        try:
            live = ecs.list_tasks(cluster=cluster, desiredStatus="RUNNING")["taskArns"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ClusterNotFoundException":
                return
            raise
        if not live:
            break
        if time.monotonic() >= deadline:
            raise AssertionError(f"{len(live)} task(s) in {cluster} still RUNNING after {timeout_s:.0f}s")
        time.sleep(interval_s)
    while True:
        try:
            ecs.delete_cluster(cluster=cluster)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ClusterNotFoundException":
                return
            if code not in ("ClusterContainsTasksException", "UpdateInProgressException"):
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
