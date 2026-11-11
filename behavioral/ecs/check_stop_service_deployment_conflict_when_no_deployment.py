"""stop-service-deployment-conflict-when-no-deployment."""
from __future__ import annotations

import time
from typing import Any

CHECK = "stop-service-deployment-conflict-when-no-deployment"
GROUP = "error-semantics"
SERVICES = ["ecs"]

from behavioral_harness import tags


def _error(fn):
    """Call fn(); return its (error code, error message). An unexpected success raises,
    so accepting a call AWS rejects fails as an acceptance, not as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StopServiceDeployment raises ConflictException against a deployment that
    already reached a terminal state, but succeeds (transitions the deployment
    toward a stopped state) against a genuinely in-progress deployment."""
    ecs = ctx.client("ecs")
    cluster_arn = ecs.create_cluster(clusterName=ctx.unique_name("sim2real-ecs-stopdep-"))["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_arn))

    task_def_arn = ecs.register_task_definition(
        family=ctx.unique_name("sim2real-ecs-stopdep-td-"),
        requiresCompatibilities=["EC2"],
        networkMode="bridge",
        containerDefinitions=[
            {"name": "app", "image": "public.ecr.aws/amazonlinux/amazonlinux:2023", "cpu": 128, "memory": 128, "essential": True}
        ],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))

    # --- Part 1: a desiredCount=0 service converges to a terminal (SUCCESSFUL)
    # deployment almost immediately -- StopServiceDeployment on it must conflict.
    svc_done_name = ctx.unique_name("sim2real-ecs-stopdep-done-")
    ecs.create_service(
        cluster=cluster_arn, serviceName=svc_done_name, taskDefinition=task_def_arn,
        desiredCount=0, launchType="EC2",
    )
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=cluster_arn, service=svc_done_name, force=True))

    arn_done = _first_deployment_arn(ctx, ecs, cluster_arn, svc_done_name)
    detail_done = _poll_until(
        lambda: ecs.describe_service_deployments(serviceDeploymentArns=[arn_done])["serviceDeployments"][0],
        lambda d: d["status"] in ("SUCCESSFUL", "ROLLBACK_SUCCESSFUL"),
        timeout_s=60,
    )
    assert detail_done["status"] == "SUCCESSFUL", (
        f"expected a desiredCount=0 deployment to converge to SUCCESSFUL, got {detail_done['status']}"
    )

    code, message = _error(lambda: ecs.stop_service_deployment(serviceDeploymentArn=arn_done))
    assert code == "ConflictException", f"expected ConflictException on terminal deployment, got {code}"
    expected_message = f"ServiceDeployment is stopping or has already finished for arn: {arn_done}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # the forbidden effect did not happen: status is unchanged
    still_done = ecs.describe_service_deployments(serviceDeploymentArns=[arn_done])["serviceDeployments"][0]
    assert still_done["status"] == "SUCCESSFUL", f"status mutated by rejected StopServiceDeployment: {still_done['status']}"

    # --- Part 2 (positive control): desiredCount=1 with zero container
    # instances in the cluster can never place its task, so the deployment
    # stays genuinely IN_PROGRESS -- StopServiceDeployment must succeed on it.
    svc_stuck_name = ctx.unique_name("sim2real-ecs-stopdep-stuck-")
    ecs.create_service(
        cluster=cluster_arn, serviceName=svc_stuck_name, taskDefinition=task_def_arn,
        desiredCount=1, launchType="EC2",
    )
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=cluster_arn, service=svc_stuck_name, force=True))

    arn_stuck = _first_deployment_arn(ctx, ecs, cluster_arn, svc_stuck_name)
    detail_stuck = _poll_until(
        lambda: ecs.describe_service_deployments(serviceDeploymentArns=[arn_stuck])["serviceDeployments"][0],
        lambda d: d["status"] in ("IN_PROGRESS", "PENDING"),
        timeout_s=30,
    )
    assert detail_stuck["status"] in ("IN_PROGRESS", "PENDING"), (
        f"expected an unplaceable service to stay in-flight, got {detail_stuck['status']}"
    )

    resp = ecs.stop_service_deployment(serviceDeploymentArn=arn_stuck)
    assert resp["serviceDeploymentArn"] == arn_stuck, (
        f"expected StopServiceDeployment to echo the target ARN {arn_stuck!r}, got {resp!r}"
    )

    # Poll past the transient STOP_REQUESTED / ROLLBACK_IN_PROGRESS states to a terminal one.
    stopped = _poll_until(
        lambda: ecs.describe_service_deployments(serviceDeploymentArns=[arn_stuck])["serviceDeployments"][0],
        lambda d: d["status"] in ("STOPPED", "SUCCESSFUL", "ROLLBACK_SUCCESSFUL", "ROLLBACK_FAILED"),
        timeout_s=300,
        interval_s=5.0,
    )
    # The service's first deployment has no earlier revision to roll back to, so the
    # user-requested rollback ends in ROLLBACK_FAILED.
    assert stopped["status"] == "ROLLBACK_FAILED", (
        f"StopServiceDeployment on a first deployment did not end in ROLLBACK_FAILED: {stopped!r}"
    )
    assert stopped.get("statusReason") == "No rollback candidate was found to run the rollback.", (
        f"unexpected statusReason on the stopped deployment: {stopped!r}"
    )
    assert stopped.get("rollback", {}).get("reason") == "Service deployment rolled back by user.", (
        f"unexpected rollback reason on the stopped deployment: {stopped!r}"
    )

# ===== helpers =====
def _first_deployment_arn(ctx, ecs, cluster_arn: str, service_name: str) -> str:
    arns = _poll_until(
        lambda: ecs.list_service_deployments(cluster=cluster_arn, service=service_name)["serviceDeployments"],
        lambda deployments: len(deployments) >= 1,
        timeout_s=30,
    )
    return arns[0]["serviceDeploymentArn"]


def _poll_until(probe, predicate, timeout_s: float = 30.0, interval_s: float = 2.0) -> Any:
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        result = probe()
        if predicate(result):
            return result
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last result={result}")


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
