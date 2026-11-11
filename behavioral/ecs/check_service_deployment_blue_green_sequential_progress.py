"""service-deployment-blue-green-sequential-progress."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "service-deployment-blue-green-sequential-progress"
GROUP = 'overly-permissive'
SERVICES = ['ecs']


FARGATE_CONTAINER_DEFS = [
    {
        "name": "app",
        "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
        "essential": True,
        "command": ["sleep", "600"],
    }
]


def _error(fn):
    """Return (code, message) of the ClientError *fn* raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _delete_cluster_when_drained(ecs, cluster: str, timeout_s: float = 420.0) -> None:
    """Stop any task left in *cluster*, then delete it once ECS reports no active tasks; a
    force-deleted service's tasks keep the cluster busy until STOPPED, so the delete is retried
    until *timeout_s* and the last error propagates on timeout."""
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
    """(subnets, security group) for Fargate (awsvpc) tasks from the run's shared network."""
    net = ctx.network()
    return list(net.subnet_ids), net.security_group_id


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A BLUE_GREEN deployment with PRE_SCALE_UP and POST_SCALE_UP pause hooks advances one stage
    per ContinueServiceDeployment(CONTINUE), in order; a bogus hookId on a paused deployment is
    rejected rather than silently advancing it."""
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

    svc_name = ctx.unique_name("bg-svc-")
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
                    "lifecycleStages": ["PRE_SCALE_UP"],
                    "timeoutConfiguration": {"timeoutInMinutes": 10, "action": "ROLLBACK"},
                },
                {
                    "targetType": "PAUSE",
                    "lifecycleStages": ["POST_SCALE_UP"],
                    "timeoutConfiguration": {"timeoutInMinutes": 10, "action": "ROLLBACK"},
                },
            ],
        },
    )["service"]
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=name, service=svc_name, force=True))
    assert created["deploymentConfiguration"]["strategy"] == "BLUE_GREEN", (
        f"expected BLUE_GREEN strategy, got {created['deploymentConfiguration'].get('strategy')}"
    )

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

    hook1 = _poll_until(_hook_awaiting, lambda hk: hk is not None, timeout_s=120)

    # overly-permissive boundary: a bogus hookId must not advance a paused deployment.
    bad_code, bad_message = _error(
        lambda: ecs.continue_service_deployment(
            serviceDeploymentArn=deployment_arn, hookId="ecs-pause-not-a-real-hook-id", action="CONTINUE"
        )
    )
    assert bad_code == "InvalidParameterException", f"expected InvalidParameterException for a bogus hookId, got {bad_code}"
    assert bad_message == "Invalid hookId: hookId must follow the format: ecs-{hookType}-{id}", f"unexpected message for a bogus hookId: {bad_message!r}"
    still_hook1 = _hook_awaiting()
    assert still_hook1 is not None and still_hook1["hookId"] == hook1["hookId"], (
        "a rejected bogus-hookId call must not have silently advanced the real paused hook"
    )

    ecs.continue_service_deployment(
        serviceDeploymentArn=deployment_arn, hookId=hook1["hookId"], action="CONTINUE"
    )

    hook2 = _poll_until(
        _hook_awaiting,
        lambda hk: hk is not None and hk["hookId"] != hook1["hookId"],
        timeout_s=240,
    )
    assert hook2["hookId"] != hook1["hookId"], "expected a distinct hookId for the second pause stage"

    ecs.continue_service_deployment(
        serviceDeploymentArn=deployment_arn, hookId=hook2["hookId"], action="CONTINUE"
    )

    final_desc = _poll_until(
        _describe,
        lambda d: d["status"] in ("SUCCESSFUL", "IN_PROGRESS")
        and not any(hk["status"] == "AWAITING_ACTION" for hk in d.get("lifecycleHookDetails", [])),
        timeout_s=300,
    )
    assert not any(
        hk["status"] == "AWAITING_ACTION" for hk in final_desc.get("lifecycleHookDetails", [])
    ), f"expected no remaining awaiting-action hooks, got {final_desc.get('lifecycleHookDetails')}"

    target_rev_arn = final_desc.get("targetServiceRevision", {}).get("arn")
    if target_rev_arn:
        revisions = ecs.describe_service_revisions(serviceRevisionArns=[target_rev_arn])[
            "serviceRevisions"
        ]
        assert any(r.get("taskDefinition") == td_arn for r in revisions), (
            f"expected the target service revision to reference {td_arn}, got {revisions}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
