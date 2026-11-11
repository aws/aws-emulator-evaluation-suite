"""continue-service-deployment-rejects-non-waiting-state."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "continue-service-deployment-rejects-non-waiting-state"
GROUP = "concurrency"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ContinueServiceDeployment on a deployment not paused at a lifecycle hook is rejected."""

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
    assert len(deployments) >= 1, f"expected at least one service deployment to exist, got {len(deployments)}"
    deployment_arn = deployments[0]["serviceDeploymentArn"]

    described = ecs.describe_service_deployments(serviceDeploymentArns=[deployment_arn])["serviceDeployments"][0]
    assert described["status"] in ("PENDING", "IN_PROGRESS"), f"unexpected pre-continue status {described['status']}"
    # There is no lifecycle hook configured on this plain rolling-update deployment, so it can
    # never be legitimately "paused" awaiting continuation.
    assert not described.get("lifecycleHookDetails"), "deployment unexpectedly has a paused lifecycle hook"

    # --- negative: continuing with a hookId that isn't a currently-paused hook is rejected. ---
    try:
        ecs.continue_service_deployment(
            serviceDeploymentArn=deployment_arn, hookId="not-a-paused-hook", action="CONTINUE"
        )
        raise AssertionError("ContinueServiceDeployment on a non-waiting deployment unexpectedly succeeded")
    except ClientError as e:
        assert _code(e) == "InvalidParameterException", f"expected InvalidParameterException, got {_code(e)}"
        message = e.response["Error"]["Message"]
        assert message == "Invalid hookId: hookId must follow the format: ecs-{hookType}-{id}", f"unexpected message: {message!r}"

    # The deployment must not have advanced as a side effect of the rejected call.
    recheck = ecs.describe_service_deployments(serviceDeploymentArns=[deployment_arn])["serviceDeployments"][0]
    assert recheck["status"] in ("PENDING", "IN_PROGRESS"), (
        f"deployment status changed after a rejected ContinueServiceDeployment call: {recheck['status']}"
    )

    # --- boundary: a malformed/non-existent deployment ARN is also rejected. Real deployment
    # ARNs embed a specific deployment-id token format, so substituting a wholly synthetic
    # suffix fails ECS's own ARN-shape validation before it ever gets to a resource lookup --
    # i.e. it is rejected with the same InvalidParameterException as the bad-hookId case above,
    # not a distinct "not found" error. ---
    bogus_arn = deployment_arn.rsplit("/", 1)[0] + "/0000000000000000000000000000000000000000"
    try:
        ecs.continue_service_deployment(serviceDeploymentArn=bogus_arn, hookId="not-a-paused-hook", action="CONTINUE")
        raise AssertionError("ContinueServiceDeployment on a non-existent deployment ARN unexpectedly succeeded")
    except ClientError as e:
        assert _code(e) == "InvalidParameterException", (
            f"expected InvalidParameterException for a bogus/malformed ARN, got {_code(e)}"
        )
        message = e.response["Error"]["Message"]
        assert message == "The ServiceDeployment ARN is invalid.", f"unexpected message: {message!r}"

    # The real deployment must still be untouched by the rejected bogus-ARN call — an
    # independent read, at the destination, is the terminal claim of this check.
    final = ecs.describe_service_deployments(serviceDeploymentArns=[deployment_arn])["serviceDeployments"][0]
    assert final["status"] in ("PENDING", "IN_PROGRESS"), (
        f"deployment status changed after a rejected bogus-ARN ContinueServiceDeployment call: {final['status']}"
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
    check_tags = [{"key": "sim2real-check", "value": CHECK}]
    cluster_name = ctx.unique_name("sim2real-ecs-contdep-")
    ecs.create_cluster(clusterName=cluster_name, tags=check_tags)
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_name))

    family = ctx.unique_name("sim2real-ecs-contdep-td-")
    td = ecs.register_task_definition(
        family=family,
        containerDefinitions=[
            {"name": "c", "image": "public.ecr.aws/docker/library/busybox:1.36", "memory": 64, "essential": True}
        ],
        tags=check_tags,
    )["taskDefinition"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, td["taskDefinitionArn"]))

    service_name = ctx.unique_name("sim2real-ecs-contdep-svc-")
    try:
        ecs.create_service(
            cluster=cluster_name,
            serviceName=service_name,
            taskDefinition=td["taskDefinitionArn"],
            desiredCount=1,
            launchType="EC2",
            schedulingStrategy="REPLICA",
            tags=check_tags,
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
