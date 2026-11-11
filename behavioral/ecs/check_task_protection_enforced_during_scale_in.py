"""task-protection-enforced-during-scale-in."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "task-protection-enforced-during-scale-in"
GROUP = 'task-hardening'
SERVICES = ['ecs']

_ECS_TAGS = [{"key": "sim2real", "value": "true"}]


FARGATE_CONTAINER_DEFS = [
    {
        "name": "app",
        "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
        "essential": True,
        "command": ["sleep", "600"],
    }
]


def _fargate_network(ctx):
    """(subnets, security group) for Fargate (awsvpc) tasks from the run's shared network."""
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


def _error(fn):
    """Call fn(); return its botocore (code, message). A call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _task_id(arn):
    return arn.rsplit("/", 1)[-1]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """When a two-task service scales in to one, ECS stops the unprotected task and keeps the one
    protected via UpdateTaskProtection; expiresInMinutes outside 1-2880 is rejected."""
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-behav-ecs-cluster-")
    ecs.create_cluster(clusterName=name, tags=_ECS_TAGS)
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, name))
    family = ctx.unique_name("sim2real-behav-ecs-taskdef-fg-")
    task_def = ecs.register_task_definition(
        family=family,
        containerDefinitions=FARGATE_CONTAINER_DEFS,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        tags=_ECS_TAGS,
    )["taskDefinition"]
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[task_def["taskDefinitionArn"]]))
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=task_def["taskDefinitionArn"]))

    # overly-permissive boundary: an out-of-range expiresInMinutes must be
    # rejected before anything is applied.
    error = _error(
        lambda: ecs.update_task_protection(
            cluster=name, tasks=["0" * 32], protectionEnabled=True, expiresInMinutes=5000
        )
    )
    expected = ("InvalidParameterException", "expiresInMinutes must be at most 2880")
    assert error == expected, (
        f"expected {expected!r} for expiresInMinutes=5000 (outside the documented "
        f"1-2880 range), got {error!r}"
    )

    subnets, sg = _fargate_network(ctx)
    service_name = ctx.unique_name("sim2real-behav-ecs-svc-")
    ecs.create_service(
        cluster=name,
        serviceName=service_name,
        taskDefinition=task_def["taskDefinitionArn"],
        desiredCount=2,
        launchType="FARGATE",
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": subnets[:1],
                "securityGroups": [sg],
                "assignPublicIp": "ENABLED",
            }
        },
        tags=_ECS_TAGS,
    )
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=name, service=service_name, force=True))

    def _running_task_arns():
        return ecs.list_tasks(cluster=name, serviceName=service_name, desiredStatus="RUNNING")["taskArns"]

    running = _poll_until(
        _running_task_arns,
        lambda arns: len(arns) == 2,
        timeout_s=180,
        interval_s=5,
        description="the service's two tasks both reach RUNNING",
    )
    assert len(running) == 2, running
    protected_arn, other_arn = running[0], running[1]

    protect_resp = ecs.update_task_protection(
        cluster=name, tasks=[protected_arn], protectionEnabled=True, expiresInMinutes=10
    )
    # Registered right after enabling protection so LIFO runs it BEFORE the
    # delete_service(force) cleanup: a still-protected task cannot be stopped by
    # scale-in OR force-delete until its 10-min TTL lapses, which would otherwise
    # pin the task's ENI in the subnet and make the dedicated-VPC teardown leak.
    ctx.on_cleanup(
        lambda: ecs.update_task_protection(
            cluster=name, tasks=[protected_arn], protectionEnabled=False
        )
    )
    assert not protect_resp.get("failures"), protect_resp.get("failures")

    # UpdateTaskProtection/GetTaskProtection's response taskArn can omit the
    # cluster-name path segment — match on the trailing task-id component.
    protected_id = _task_id(protected_arn)
    protected_entries = {_task_id(p["taskArn"]): p for p in protect_resp.get("protectedTasks", [])}
    assert protected_entries.get(protected_id, {}).get("protectionEnabled") is True, protect_resp

    get_resp = ecs.get_task_protection(cluster=name, tasks=[protected_arn])
    got_entries = {_task_id(p["taskArn"]): p for p in get_resp.get("protectedTasks", [])}
    assert got_entries.get(protected_id, {}).get("protectionEnabled") is True, get_resp

    ecs.update_service(cluster=name, service=service_name, desiredCount=1)

    def _describe_both():
        return {
            t["taskArn"]: t
            for t in ecs.describe_tasks(cluster=name, tasks=[protected_arn, other_arn])["tasks"]
        }

    final_states = _poll_until(
        _describe_both,
        lambda states: states.get(other_arn, {}).get("lastStatus") == "STOPPED",
        timeout_s=180,
        interval_s=5,
        description="scale-in stops the UNPROTECTED task",
    )
    assert final_states[other_arn]["lastStatus"] == "STOPPED", final_states[other_arn]
    assert final_states[protected_arn]["lastStatus"] == "RUNNING", (
        f"the protected task must be excluded from scale-in stop selection, got "
        f"{final_states[protected_arn]}"
    )

    still_protected = ecs.get_task_protection(cluster=name, tasks=[protected_arn])
    still_entries = {_task_id(p["taskArn"]): p for p in still_protected.get("protectedTasks", [])}
    assert still_entries.get(protected_id, {}).get("protectionEnabled") is True, still_protected

    ecs.update_service(cluster=name, service=service_name, desiredCount=0)


def _drain_and_delete_ecs_cluster(ecs, cluster, timeout_s=900.0, interval_s=2.0):
    """Stop a cluster's services and tasks, wait until they stop, then delete it: DeleteCluster is
    refused while services or tasks remain, and a running task's ENI blocks network deletion."""
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
                    "ServiceNotFoundException", "ServiceNotActiveException",
                    "ClusterNotFoundException",
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
