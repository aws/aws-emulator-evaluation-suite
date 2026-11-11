"""stop-service-deployment-already-stopped-is-idempotent."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "stop-service-deployment-already-stopped-is-idempotent"
GROUP = "concurrency"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A second StopServiceDeployment on an already-stopped deployment is idempotent: it does not
    error, and it does not re-trigger the stop/rollback effect (status is unchanged)."""

    ecs = ctx.client("ecs")
    cluster_name, service_name = _create_stuck_service(ctx)

    def _list_deployments():
        return ecs.list_service_deployments(cluster=cluster_name, service=service_name)["serviceDeployments"]

    try:
        deployments = _poll_until(
            _list_deployments,
            lambda d: len(d) >= 1,
            timeout_s=60.0,
            interval_s=3.0,
        )
    except ClientError as e:
        if _code(e) == "UnsupportedFeatureException":
            raise AssertionError("service deployment feature not available in this Region/account")
        raise
    assert len(deployments) >= 1, f"expected at least one service deployment to be listed, got {deployments!r}"
    deployment_arn = deployments[0]["serviceDeploymentArn"]

    described = ecs.describe_service_deployments(serviceDeploymentArns=[deployment_arn])["serviceDeployments"][0]
    assert described["status"] in ("PENDING", "IN_PROGRESS"), f"unexpected pre-stop status {described['status']}"

    # --- positive control: stopping an in-progress deployment succeeds. ---
    ecs.stop_service_deployment(serviceDeploymentArn=deployment_arn, stopType="ROLLBACK")
    stopped = _poll_until(
        lambda: ecs.describe_service_deployments(serviceDeploymentArns=[deployment_arn])["serviceDeployments"][0],
        lambda d: d["status"] in ("STOPPED", "ROLLBACK_SUCCESSFUL", "ROLLBACK_FAILED"),
        timeout_s=120.0,
        interval_s=4.0,
    )
    terminal_status = stopped["status"]
    assert terminal_status in ("STOPPED", "ROLLBACK_SUCCESSFUL", "ROLLBACK_FAILED"), (
        f"expected a terminal stop/rollback status after the positive-control stop, got {terminal_status!r}"
    )

    # --- second call on an already-stopped deployment: like other ECS "stop" actions (e.g.
    # StopTask against an already-stopped task), StopServiceDeployment against a deployment
    # that is already in a terminal state is idempotent and does not raise -- but it must not
    # re-trigger the effect (no further status change / no new rollback/stop attempt). ---
    ecs.stop_service_deployment(serviceDeploymentArn=deployment_arn, stopType="ROLLBACK")

    # The effect must not have happened again: status is unchanged from the first stop, and it
    # stays that way -- not just in the single instant right after the duplicate call.
    def _describe():
        return ecs.describe_service_deployments(serviceDeploymentArns=[deployment_arn])["serviceDeployments"][0]

    observed = []
    for _ in range(3):
        recheck = _describe()
        observed.append(recheck["status"])
        assert recheck["status"] == terminal_status, (
            f"deployment status changed after duplicate stop call: {terminal_status} -> {recheck['status']}"
        )
        time.sleep(3.0)
    assert all(s == terminal_status for s in observed), (
        f"expected every repeated post-duplicate-stop read to stay {terminal_status!r}, got {observed!r}"
    )


# ===== helpers =====
def _code(e: ClientError):
    return e.response.get("Error", {}).get("Code")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _create_stuck_service(ctx):
    """Create a service with no cluster capacity so its deployment stays IN_PROGRESS indefinitely."""

    ecs = ctx.client("ecs")
    resource_tags = [{"key": "sim2real:managed", "value": "true"}]
    cluster_name = ctx.unique_name("sim2real-ecs-stopdep-")
    ecs.create_cluster(clusterName=cluster_name, tags=resource_tags)

    def _cleanup_cluster():
        # DeleteCluster rejects with ClusterContainsServicesException/ClusterContains
        # ContainerInstancesException for a beat after DeleteService returns -- the
        # service's own teardown (registered later, so it runs first under LIFO) only
        # *starts* draining, it does not block until INACTIVE. Retry within the
        # ctx.on_cleanup budget instead of giving up on the first race.
        deadline = time.monotonic() + 45.0
        while True:
            try:
                ecs.delete_cluster(cluster=cluster_name)
                return
            except ClientError as e:
                if _code(e) in (
                    "ClusterContainsServicesException",
                    "ClusterContainsContainerInstancesException",
                    "ClusterContainsTasksException",
                ) and time.monotonic() < deadline:
                    time.sleep(3.0)
                    continue
                raise

    ctx.on_cleanup(_cleanup_cluster)

    family = ctx.unique_name("sim2real-ecs-stopdep-td-")
    td = ecs.register_task_definition(
        family=family,
        containerDefinitions=[
            {"name": "c", "image": "public.ecr.aws/docker/library/busybox:1.36", "memory": 64, "essential": True}
        ],
    )["taskDefinition"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, td["taskDefinitionArn"]))

    service_name = ctx.unique_name("sim2real-ecs-stopdep-svc-")
    try:
        ecs.create_service(
            cluster=cluster_name,
            serviceName=service_name,
            taskDefinition=td["taskDefinitionArn"],
            desiredCount=1,
            launchType="EC2",
            schedulingStrategy="REPLICA",
            tags=resource_tags,
        )
    except ClientError as e:
        raise AssertionError(f"CreateService rejected: {_code(e)}")
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=cluster_name, service=service_name, force=True))
    return cluster_name, service_name


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
