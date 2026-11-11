"""service-deployment-hook-wait-window."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "service-deployment-hook-wait-window"
GROUP = 'service-deployment'
SERVICES = ['ecs']


FARGATE_CONTAINER_DEFS = [
    {
        "name": "app",
        "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
        "essential": True,
        "command": ["sleep", "600"],
    }
]


def _delete_cluster_when_drained(ecs, cluster: str, timeout_s: float = 420.0) -> None:
    """Stop any task left in *cluster*, then delete it once ECS reports no active tasks.

    A force-deleted service's tasks keep the cluster busy until they reach STOPPED, so the
    delete is retried on ClusterContainsTasksException / ClusterContainsServicesException
    until *timeout_s*; on timeout the last error propagates.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            for task_arn in ecs.list_tasks(cluster=cluster).get("taskArns", []):
                try:
                    ecs.stop_task(cluster=cluster, task=task_arn, reason="check cleanup")
                except ClientError as err:
                    if err.response["Error"]["Code"] != "ClusterNotFoundException":
                        raise
            ecs.delete_cluster(cluster=cluster)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ClusterNotFoundException":
                return
            if code not in ("ClusterContainsTasksException", "ClusterContainsServicesException"):
                raise
            if time.monotonic() >= deadline:
                raise
        time.sleep(10)


def _poll_until(fn, pred, *, timeout_s, interval_s=5):
    deadline = time.monotonic() + timeout_s
    while True:
        val = fn()
        if pred(val):
            return val
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last={val!r})")
        time.sleep(interval_s)


def _fargate_network(ctx):
    """(subnets, security group) for Fargate (awsvpc) tasks from the run's shared network (ctx.network), the
    same on every target; the run owns and deletes the network."""
    net = ctx.network()
    return list(net.subnet_ids), net.security_group_id


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A BLUE_GREEN lifecycle hook becomes AWAITING_ACTION only after ECS has progressed the deployment,
    not instantly on CreateService; once continued, its window closes and a repeated CONTINUE
    is an idempotent no-op, never a re-triggered pause.
    """
    ecs = ctx.client("ecs")
    subnets, sg = _fargate_network(ctx)
    net_cfg = {
        "awsvpcConfiguration": {"subnets": subnets[:1], "securityGroups": [sg], "assignPublicIp": "ENABLED"}
    }

    cluster = ecs.create_cluster(clusterName=ctx.unique_name("sim2real-behav-ecs-cluster-"))["cluster"]
    name = cluster["clusterName"]
    ctx.on_cleanup(lambda: _delete_cluster_when_drained(ecs, name))

    family = ctx.unique_name("sim2real-behav-ecs-taskdef-fg-")
    td = ecs.register_task_definition(
        family=family,
        containerDefinitions=FARGATE_CONTAINER_DEFS,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
    )["taskDefinition"]
    td_arn = td["taskDefinitionArn"]
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[td_arn]))
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=td_arn))

    created_at = time.time()
    svc_name = ctx.unique_name("bg-wait-svc-")
    created = ecs.create_service(
        cluster=name,
        serviceName=svc_name,
        taskDefinition=td_arn,
        desiredCount=1,
        launchType="FARGATE",
        networkConfiguration=net_cfg,
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
    assert created["deploymentConfiguration"]["strategy"] == "BLUE_GREEN"

    listed_dep = _poll_until(
        lambda: ecs.list_service_deployments(cluster=name, service=svc_name).get("serviceDeployments", []),
        lambda deps: len(deps) > 0,
        timeout_s=60,
        interval_s=3,
    )
    deployment_arn = listed_dep[0]["serviceDeploymentArn"]

    def _describe() -> dict:
        return ecs.describe_service_deployments(serviceDeploymentArns=[deployment_arn])[
            "serviceDeployments"
        ][0]

    def _hook_awaiting():
        for hook in _describe().get("lifecycleHookDetails", []):
            if hook.get("status") == "AWAITING_ACTION":
                return hook
        return None

    hook = _poll_until(_hook_awaiting, lambda hk: hk is not None, timeout_s=180)
    elapsed_to_pause = time.time() - created_at
    assert elapsed_to_pause >= 5, (
        f"expected the hook's actionable wait window to reflect genuine elapsed time (>= 5s), "
        f"but it became actionable after only {elapsed_to_pause:.1f}s"
    )

    ecs.continue_service_deployment(
        serviceDeploymentArn=deployment_arn, hookId=hook["hookId"], action="CONTINUE"
    )

    closed = _poll_until(
        _hook_awaiting,
        lambda hk: hk is None or hk["hookId"] != hook["hookId"],
        timeout_s=60,
    )
    assert closed is None or closed["hookId"] != hook["hookId"], (
        "continuing a hook must close ITS OWN actionable window, not leave it re-awaiting"
    )

    # re-continuing the same, already-continued hookId is an idempotent no-op on AWS (it
    # succeeds) and must not reopen the window.
    ecs.continue_service_deployment(
        serviceDeploymentArn=deployment_arn, hookId=hook["hookId"], action="CONTINUE"
    )
    still_closed = _hook_awaiting()
    assert still_closed is None or still_closed["hookId"] != hook["hookId"], (
        "re-continuing an already-closed hook must not reopen ITS actionable window"
    )

    final = _poll_until(
        _describe,
        lambda d: d["status"] in ("SUCCESSFUL", "IN_PROGRESS")
        and not any(hk["status"] == "AWAITING_ACTION" for hk in d.get("lifecycleHookDetails", [])),
        timeout_s=240,
    )
    assert not any(
        hk["status"] == "AWAITING_ACTION" for hk in final.get("lifecycleHookDetails", [])
    ), f"expected no remaining awaiting-action hooks, got {final.get('lifecycleHookDetails')}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
