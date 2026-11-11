"""essential-container-exit-stops-task-and-sidecar."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "essential-container-exit-stops-task-and-sidecar"
GROUP = 'task-lifecycle'
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
    """When a non-essential container exits the task keeps running; when an essential container
    exits the task stops with stopCode EssentialContainerExited, its exitCode preserved, and the
    still-running non-essential sidecar is stopped too."""
    ecs = ctx.client("ecs")
    cluster = ctx.unique_name("sim2real-behav-ecs-cluster-")
    ecs.create_cluster(clusterName=cluster)
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, cluster))
    subnets, sg = _fargate_network(ctx)
    net_cfg = {
        "awsvpcConfiguration": {
            "subnets": subnets[:1],
            "securityGroups": [sg],
            "assignPublicIp": "ENABLED",
        }
    }
    image = "public.ecr.aws/docker/library/busybox:1.36"

    def _register(defs: list[dict]) -> str:
        arn = ecs.register_task_definition(
            family=ctx.unique_name("sim2real-behav-ecs-taskdef-fg-"),
            containerDefinitions=defs,
            networkMode="awsvpc",
            requiresCompatibilities=["FARGATE"],
            cpu="256",
            memory="512",
        )["taskDefinition"]["taskDefinitionArn"]
        ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[arn]))
        ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=arn))
        return arn

    def _run(td_arn: str) -> str:
        resp = ecs.run_task(
            cluster=cluster,
            taskDefinition=td_arn,
            launchType="FARGATE",
            count=1,
            networkConfiguration=net_cfg,
        )
        assert not resp.get("failures"), f"unexpected RunTask failures: {resp.get('failures')}"
        arn = resp["tasks"][0]["taskArn"]
        ctx.on_cleanup(
            lambda: ecs.stop_task(cluster=cluster, task=arn, reason="behavioral-cleanup")
        )
        return arn

    def _task(arn: str) -> dict:
        return ecs.describe_tasks(cluster=cluster, tasks=[arn])["tasks"][0]

    def _container(task: dict, name: str) -> dict:
        for c in task.get("containers", []):
            if c.get("name") == name:
                return c
        raise AssertionError(f"container {name!r} missing from task record {task.get('containers')}")

    # ---- Control: a NON-essential container exiting must NOT stop the task ----
    control_arn = _register(
        [
            {"name": "main", "image": image, "essential": True, "command": ["sh", "-c", "sleep 900"]},
            {
                "name": "worker",
                "image": image,
                "essential": False,
                "command": ["sh", "-c", "sleep 5; exit 0"],
            },
        ]
    )
    control_task_arn = _run(control_arn)
    control = _poll_until(
        lambda: _task(control_task_arn),
        lambda t: _container(t, "worker").get("lastStatus") == "STOPPED"
        or t["lastStatus"] == "STOPPED",
        timeout_s=600,
        interval_s=10,
        description="the non-essential worker container exits",
    )
    assert control["lastStatus"] == "RUNNING", (
        "a non-essential container exiting must NOT stop the task, got lastStatus="
        f"{control['lastStatus']!r} stopCode={control.get('stopCode')!r} "
        f"stoppedReason={control.get('stoppedReason')!r}"
    )
    assert _container(control, "worker").get("exitCode") == 0, _container(control, "worker")
    assert _container(control, "main").get("lastStatus") == "RUNNING", (
        f"the essential container must still be RUNNING, got {_container(control, 'main')}"
    )

    # ---- The essential container exiting must tear the whole task down ----
    essential_arn = _register(
        [
            {
                "name": "main",
                "image": image,
                "essential": True,
                "command": ["sh", "-c", "sleep 5; exit 3"],
            },
            {
                "name": "sidecar",
                "image": image,
                "essential": False,
                "command": ["sh", "-c", "sleep 900"],
            },
        ]
    )
    essential_task_arn = _run(essential_arn)
    stopped = _poll_until(
        lambda: _task(essential_task_arn),
        lambda t: t["lastStatus"] == "STOPPED",
        timeout_s=600,
        interval_s=10,
        description="the task stops because its essential container exited",
    )
    assert stopped.get("stopCode") == "EssentialContainerExited", (
        "the task must be attributed to the essential container's exit, got stopCode="
        f"{stopped.get('stopCode')!r} stoppedReason={stopped.get('stoppedReason')!r}"
    )
    assert "Essential container in task exited" in (stopped.get("stoppedReason") or ""), (
        f"unexpected stoppedReason: {stopped.get('stoppedReason')!r}"
    )
    main = _container(stopped, "main")
    assert main.get("exitCode") == 3, (
        f"the essential container's own exitCode must be preserved, got {main}"
    )
    sidecar = _container(stopped, "sidecar")
    assert sidecar.get("lastStatus") == "STOPPED", (
        "the never-exiting non-essential sidecar must be torn down with the task, got "
        f"{sidecar}"
    )
    assert stopped.get("stoppedAt") is not None, f"stoppedAt must be set, got {stopped!r}"


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
