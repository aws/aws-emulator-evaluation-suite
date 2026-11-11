"""run-task-propagate-tags-from-task-definition."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "run-task-propagate-tags-from-task-definition"
GROUP = 'tagging'
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


@tags("axis:happy-path", "cap:c3", "concern:representation", "plane:control")
def run(ctx) -> None:
    """With propagateTags=TASK_DEFINITION and enableECSManagedTags the task carries every task definition
    tag plus aws:ecs:clusterName, while a task from the same definition without both options carries
    neither: tags are derived server-side, not stored flags."""
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

    td_tags = [
        {"key": "sim2real-propagated", "value": "yes"},
        {"key": "sim2real-owner", "value": "simparity"},
    ]
    td_arn = ecs.register_task_definition(
        family=ctx.unique_name("sim2real-behav-ecs-taskdef-fg-"),
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "essential": True,
                "command": ["sh", "-c", "sleep 600"],
            }
        ],
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        tags=td_tags,
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[td_arn]))
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=td_arn))

    registered = {
        t["key"]: t["value"]
        for t in ecs.list_tags_for_resource(resourceArn=td_arn).get("tags", [])
    }
    assert registered.get("sim2real-propagated") == "yes", (
        f"the task definition's own tags must round-trip before propagation is testable, got {registered}"
    )

    def _run(**kwargs) -> str:
        resp = ecs.run_task(
            cluster=cluster,
            taskDefinition=td_arn,
            launchType="FARGATE",
            count=1,
            networkConfiguration=net_cfg,
            **kwargs,
        )
        assert not resp.get("failures"), f"unexpected RunTask failures: {resp.get('failures')}"
        arn = resp["tasks"][0]["taskArn"]
        ctx.on_cleanup(
            lambda: ecs.stop_task(cluster=cluster, task=arn, reason="behavioral-cleanup")
        )
        return arn

    propagated_arn = _run(propagateTags="TASK_DEFINITION", enableECSManagedTags=True)
    plain_arn = _run()

    def _task_tags(arn: str) -> dict:
        return {
            t["key"]: t["value"]
            for t in ecs.list_tags_for_resource(resourceArn=arn).get("tags", [])
        }

    got = _poll_until(
        lambda: _task_tags(propagated_arn),
        lambda d: "sim2real-propagated" in d,
        timeout_s=180,
        interval_s=10,
        description="the propagated task-definition tags become visible on the task",
    )
    for t in td_tags:
        assert got.get(t["key"]) == t["value"], (
            f"propagateTags=TASK_DEFINITION must copy {t} onto the task, got {got}"
        )
    assert got.get("aws:ecs:clusterName") == cluster, (
        "enableECSManagedTags=True must add the managed aws:ecs:clusterName tag with the cluster "
        f"name as its value, got {got}"
    )

    plain = _task_tags(plain_arn)
    for t in td_tags:
        assert t["key"] not in plain, (
            f"a task launched WITHOUT propagateTags must not carry {t['key']!r}, got {plain}"
        )
    managed = [k for k in plain if k.startswith("aws:ecs:")]
    assert not managed, (
        f"a task launched WITHOUT enableECSManagedTags must carry no aws:ecs: managed tags, got {managed}"
    )

    included = ecs.describe_tasks(
        cluster=cluster, tasks=[propagated_arn], include=["TAGS"]
    )["tasks"][0]
    described = {t["key"]: t["value"] for t in included.get("tags", [])}
    assert described.get("sim2real-propagated") == "yes", (
        f"DescribeTasks include=['TAGS'] must surface the same tag set, got {described}"
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
