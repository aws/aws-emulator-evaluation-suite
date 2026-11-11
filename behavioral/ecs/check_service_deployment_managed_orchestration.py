"""service-deployment-managed-orchestration."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "service-deployment-managed-orchestration"
GROUP = 'service-lifecycle'
SERVICES = ['ecs']


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


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateService alone makes the BLUE_GREEN controller drive a ServiceDeployment to its pause
    hook; ContinueServiceDeployment advances past it, and re-continuing the same hookId is a
    no-op that leaves no hook AWAITING_ACTION.
    """
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-behav-ecs-cluster-")
    ecs.create_cluster(clusterName=name)
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, name))
    family = ctx.unique_name("sim2real-behav-ecs-taskdef-fg-")
    task_def = ecs.register_task_definition(
        family=family,
        containerDefinitions=FARGATE_CONTAINER_DEFS,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
    )["taskDefinition"]
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[task_def["taskDefinitionArn"]]))
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=task_def["taskDefinitionArn"]))
    subnets, sg = _fargate_network(ctx)

    svc_name = ctx.unique_name("sim2real-behav-ecs-bg-svc-")
    created = ecs.create_service(
        cluster=name,
        serviceName=svc_name,
        taskDefinition=task_def["taskDefinitionArn"],
        desiredCount=1,
        launchType="FARGATE",
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": subnets[:1],
                "securityGroups": [sg],
                "assignPublicIp": "ENABLED",
            }
        },
        deploymentConfiguration={
            "strategy": "BLUE_GREEN",
            "lifecycleHooks": [
                {
                    "targetType": "PAUSE",
                    "lifecycleStages": ["POST_SCALE_UP"],
                    "timeoutConfiguration": {"timeoutInMinutes": 10, "action": "ROLLBACK"},
                }
            ],
        },
    )["service"]
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=name, service=svc_name, force=True))
    assert created["deploymentConfiguration"]["strategy"] == "BLUE_GREEN", (
        f"expected CreateService to echo back the requested BLUE_GREEN strategy, "
        f"got {created['deploymentConfiguration']}"
    )

    def _find_deployment():
        deployments = ecs.list_service_deployments(cluster=name, service=svc_name).get(
            "serviceDeployments", []
        )
        return deployments[0] if deployments else None

    listed_dep = _poll_until(
        _find_deployment,
        lambda d: d is not None,
        timeout_s=60,
        interval_s=3,
        description="CreateService alone produces a discoverable ServiceDeployment",
    )
    deployment_arn = listed_dep["serviceDeploymentArn"]

    def _describe():
        return ecs.describe_service_deployments(serviceDeploymentArns=[deployment_arn])[
            "serviceDeployments"
        ][0]

    def _hook_awaiting():
        desc = _describe()
        for hook in desc.get("lifecycleHookDetails", []):
            if hook.get("status") == "AWAITING_ACTION":
                return hook
        return None

    hook = _poll_until(
        _hook_awaiting,
        lambda hk: hk is not None,
        timeout_s=180,
        interval_s=5,
        description="the managed controller autonomously scales up and pauses at the lifecycle hook",
    )

    target_rev_arn = _describe().get("targetServiceRevision", {}).get("arn")
    if target_rev_arn:
        revisions = ecs.describe_service_revisions(serviceRevisionArns=[target_rev_arn])[
            "serviceRevisions"
        ]
        assert any(r.get("taskDefinition") == task_def["taskDefinitionArn"] for r in revisions), (
            f"expected the target service revision to reference {task_def['taskDefinitionArn']}, "
            f"got {revisions}"
        )

    listed_after = ecs.list_service_deployments(cluster=name, service=svc_name)["serviceDeployments"]
    assert any(d["serviceDeploymentArn"] == deployment_arn for d in listed_after), listed_after

    ecs.continue_service_deployment(
        serviceDeploymentArn=deployment_arn, hookId=hook["hookId"], action="CONTINUE"
    )

    final = _poll_until(
        _describe,
        lambda d: d["status"] in ("SUCCESSFUL", "IN_PROGRESS")
        and not any(hk["status"] == "AWAITING_ACTION" for hk in d.get("lifecycleHookDetails", [])),
        timeout_s=240,
        interval_s=5,
        description="the deployment proceeds past the hook once continued",
    )
    assert not any(
        hk["status"] == "AWAITING_ACTION" for hk in final.get("lifecycleHookDetails", [])
    ), f"expected no remaining awaiting-action hooks, got {final.get('lifecycleHookDetails')}"

    # AWS accepts a repeated continue of the same hookId as an idempotent no-op.
    ecs.continue_service_deployment(
        serviceDeploymentArn=deployment_arn, hookId=hook["hookId"], action="CONTINUE"
    )
    unchanged = _describe()
    assert not any(
        hk["status"] == "AWAITING_ACTION" for hk in unchanged.get("lifecycleHookDetails", [])
    ), (
        "re-continuing an already-continued hookId must not reset any hook back to "
        f"AWAITING_ACTION, got {unchanged.get('lifecycleHookDetails')}"
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
