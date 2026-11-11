"""stop-service-deployment-terminal-state-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "stop-service-deployment-terminal-state-rejected"
GROUP = "overly-permissive"
SERVICES = ["ecs"]


_STOPPING_STATUSES = (
    "STOPPED",
    "STOP_REQUESTED",
    "ROLLBACK_IN_PROGRESS",
    "ROLLBACK_SUCCESSFUL",
    "ROLLBACK_FAILED",
)


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StopServiceDeployment on a SUCCESSFUL (terminal) deployment is rejected with
    ConflictException and leaves its status unchanged, while the same call succeeds on an
    in-progress deployment."""
    ecs = ctx.client("ecs")
    cluster_arn = _create_cluster(ctx)
    net = _fargate_network(ctx)
    td1 = _register_sleep_task_def(ctx)

    svc_name = ctx.unique_name("sim2real-behav-svc-")
    net_cfg = {
        "awsvpcConfiguration": {
            "subnets": [net["subnet_id"]],
            "securityGroups": [net["sg_id"]],
            "assignPublicIp": "ENABLED",
        }
    }
    svc = ecs.create_service(
        cluster=cluster_arn,
        serviceName=svc_name,
        taskDefinition=td1["taskDefinitionArn"],
        desiredCount=1,
        launchType="FARGATE",
        networkConfiguration=net_cfg,
    )["service"]
    svc_arn = svc["serviceArn"]
    ctx.on_cleanup(lambda: _cleanup_service(ecs, cluster_arn, svc_arn))

    _poll_until(
        lambda: ecs.describe_services(cluster=cluster_arn, services=[svc_arn])["services"][0],
        lambda s: s["runningCount"] == 1 and s["pendingCount"] == 0,
        timeout_s=300.0,
        interval_s=8.0,
    )
    listed = _poll_until(
        lambda: ecs.list_service_deployments(cluster=cluster_arn, service=svc_arn)["serviceDeployments"],
        lambda rows: bool(rows),
        timeout_s=60.0,
        interval_s=5.0,
    )
    first_deployment_arn = listed[0]["serviceDeploymentArn"]

    described = _poll_until(
        lambda: ecs.describe_service_deployments(serviceDeploymentArns=[first_deployment_arn])[
            "serviceDeployments"
        ][0],
        lambda d: d["status"] == "SUCCESSFUL",
        timeout_s=180.0,
        interval_s=6.0,
    )
    assert described["status"] == "SUCCESSFUL", (
        f"expected the initial deployment to reach SUCCESSFUL, got {described['status']}"
    )

    # --- negative: a terminal (SUCCESSFUL) deployment must reject StopServiceDeployment ---
    code, message = _error(lambda: ecs.stop_service_deployment(serviceDeploymentArn=first_deployment_arn))
    assert code == "ConflictException", f"expected ConflictException stopping a terminal deployment, got {code}"
    expected_message = f"ServiceDeployment is stopping or has already finished for arn: {first_deployment_arn}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # --- effect-absent: the rejected call must not have touched the deployment's status ---
    still = ecs.describe_service_deployments(serviceDeploymentArns=[first_deployment_arn])["serviceDeployments"][0]
    assert still["status"] == "SUCCESSFUL", (
        f"expected status to remain SUCCESSFUL after the rejected StopServiceDeployment, got {still['status']}"
    )

    # --- positive control: stop a second, still IN_PROGRESS deployment (forced via a task
    # definition swap), so the rejection above is specific to the terminal state.
    td2 = _register_sleep_task_def(ctx)
    ecs.update_service(cluster=cluster_arn, service=svc_arn, taskDefinition=td2["taskDefinitionArn"])

    second_deployment_arn = _poll_until(
        lambda: _find_deployment_excluding(ecs, cluster_arn, svc_arn, first_deployment_arn),
        lambda arn: arn is not None,
        timeout_s=60.0,
        interval_s=3.0,
    )

    resp = ecs.stop_service_deployment(serviceDeploymentArn=second_deployment_arn)
    assert resp["serviceDeploymentArn"] == second_deployment_arn, (
        f"expected StopServiceDeployment to succeed on an in-progress deployment, "
        f"got response for {resp.get('serviceDeploymentArn')!r}"
    )

    stopped = _poll_until(
        lambda: ecs.describe_service_deployments(serviceDeploymentArns=[second_deployment_arn])[
            "serviceDeployments"
        ][0],
        lambda d: d["status"] in _STOPPING_STATUSES,
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert stopped["status"] in _STOPPING_STATUSES, (
        f"expected StopServiceDeployment to move the in-progress deployment toward a stopped "
        f"state, got {stopped['status']}"
    )


def _error(fn):
    """Return (code, message) of the ClientError *fn* raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _find_deployment_excluding(ecs, cluster_arn, svc_arn, exclude_arn):
    rows = ecs.list_service_deployments(cluster=cluster_arn, service=svc_arn)["serviceDeployments"]
    for row in rows:
        if row["serviceDeploymentArn"] != exclude_arn:
            return row["serviceDeploymentArn"]
    return None


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _fargate_network(ctx):
    """The subnet and security group for Fargate (awsvpc) tasks from the run's shared network."""
    net = ctx.network()
    return {"subnet_id": net.subnet_ids[0], "sg_id": net.security_group_id}


def _create_cluster(ctx):
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-behav-cluster-")
    arn = ecs.create_cluster(clusterName=name)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _safe_delete_cluster(ecs, arn))
    return arn


def _safe_delete_cluster(ecs, arn: str) -> None:
    _drain_and_delete_ecs_cluster(ecs, arn)


def _register_sleep_task_def(ctx, family_prefix="sim2real-behav-sleep"):
    ecs = ctx.client("ecs")
    family = ctx.unique_name(f"{family_prefix}-")
    td = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        containerDefinitions=[
            {
                "name": "main",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "command": ["sleep", "900"],
                "essential": True,
            }
        ],
    )["taskDefinition"]

    def _cleanup():
        try:
            ecs.deregister_task_definition(taskDefinition=td["taskDefinitionArn"])
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and any(f in err.get("Message", "") for f in ("Unable to describe task definition", "in the process of being deleted"))
            ):
                raise
        ecs.delete_task_definitions(taskDefinitions=[td["taskDefinitionArn"]])

    ctx.on_cleanup(_cleanup)
    return td


def _cleanup_service(ecs, cluster_arn: str, svc_arn: str) -> None:
    try:
        ecs.update_service(cluster=cluster_arn, service=svc_arn, desiredCount=0)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ClusterNotFoundException",
            "NamespaceNotFoundException",
            "ServiceNotActiveException",
            "ServiceNotFoundException",
        ):
            raise
    try:
        ecs.delete_service(cluster=cluster_arn, service=svc_arn, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ClusterNotFoundException",
            "ServiceNotFoundException",
        ):
            raise


def _drain_and_delete_ecs_cluster(ecs, cluster, timeout_s=900.0, interval_s=10.0):
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
            except ClientError:
                pass
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
