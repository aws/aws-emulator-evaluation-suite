"""run-task-container-override-base64-payload-preserved."""
from __future__ import annotations

import base64
import os
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "run-task-container-override-base64-payload-preserved"
GROUP = "representation"
SERVICES = ["ecs"]

# ===== helpers =====


def _fargate_network(ctx):
    """(subnets, security group) for Fargate (awsvpc) tasks from the run's shared network (ctx.network), the
    same on every target; the run owns and deletes the network."""
    net = ctx.network()
    return list(net.subnet_ids), net.security_group_id


# ===== end helpers =====


@tags("axis:happy-path", "cap:c3", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A RunTask container override `command` entry containing a base64-encoded binary blob
    is returned byte-identical (no whitespace collapsing, no re-encoding) by a subsequent
    DescribeTasks call."""
    ecs = ctx.client("ecs")
    subnets, sg_id = _fargate_network(ctx)

    cluster_name = ctx.unique_name("sim2real-ecs-b64-")
    cluster_arn = ecs.create_cluster(clusterName=cluster_name)["cluster"]["clusterArn"]

    family = ctx.unique_name("sim2real-ecs-b64-td-")
    taskdef_arn = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        containerDefinitions=[
            {
                "name": "c",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "essential": True,
                "command": ["sleep", "30"],
            }
        ],
    )["taskDefinition"]["taskDefinitionArn"]

    def _cleanup_taskdef():
        ecs.deregister_task_definition(taskDefinition=taskdef_arn)
        ecs.delete_task_definitions(taskDefinitions=[taskdef_arn])

    ctx.on_cleanup(_cleanup_taskdef)
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, cluster_arn))

    payload_bytes = os.urandom(96)
    payload_b64 = base64.b64encode(payload_bytes).decode("ascii")

    net_cfg = {"awsvpcConfiguration": {"subnets": subnets[:1], "assignPublicIp": "ENABLED"}}
    if sg_id:
        net_cfg["awsvpcConfiguration"]["securityGroups"] = [sg_id]

    run_resp = ecs.run_task(
        cluster=cluster_arn,
        taskDefinition=taskdef_arn,
        launchType="FARGATE",
        count=1,
        networkConfiguration=net_cfg,
        overrides={"containerOverrides": [{"name": "c", "command": ["echo", payload_b64]}]},
    )
    if not run_resp.get("tasks"):
        raise AssertionError(f"RunTask placed no task: failures={run_resp.get('failures')}")
    task_arn = run_resp["tasks"][0]["taskArn"]

    def _cleanup_task():
        ecs.stop_task(cluster=cluster_arn, task=task_arn, reason="sim2real check cleanup")
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            desc = ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])["tasks"]
            if desc and desc[0]["lastStatus"] == "STOPPED":
                return
            time.sleep(3)

    ctx.on_cleanup(_cleanup_task)

    described = ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])["tasks"]
    assert described, "DescribeTasks returned no task immediately after RunTask"
    overrides = described[0]["overrides"]["containerOverrides"][0]
    assert overrides["name"] == "c", f"expected override container name 'c', got {overrides['name']!r}"
    assert overrides["command"] == ["echo", payload_b64], (
        f"base64 override payload not preserved byte-identical: {overrides['command']!r}"
    )
    # decode round trip: prove no character was altered
    decoded = base64.b64decode(overrides["command"][1])
    assert decoded == payload_bytes, (
        f"decoded override payload does not round-trip: expected {payload_bytes!r}, got {decoded!r}"
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

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
