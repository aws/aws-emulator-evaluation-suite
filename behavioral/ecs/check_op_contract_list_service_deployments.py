"""op-contract-list-service-deployments."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "op-contract-list-service-deployments"
GROUP = "error-semantics"
SERVICES = ["ecs"]

# A freshly created service has never been updated, stopped or rolled back: only these
# three of the nine modelled ServiceDeploymentStatus values are structurally reachable for
# its first deployment (the other six — STOPPED, STOP_REQUESTED and the four ROLLBACK_*
# values — require a stop or an update that this check never issues).
_FIRST_DEPLOYMENT_STATUSES = {"PENDING", "IN_PROGRESS", "SUCCESSFUL"}


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListServiceDeployments returns the deployment created by CreateService, scoped to
    that service; ServiceNotFoundException for an unknown service in an existing cluster."""
    ecs = ctx.client("ecs")

    cluster_name = ctx.unique_name("sim2real-ecs-lsd-")
    cluster_arn = ecs.create_cluster(
        clusterName=cluster_name, tags=[{"key": "sim2real", "value": CHECK}]
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_name))

    family = ctx.unique_name("sim2real-ecs-lsd-td-")
    td_arn = ecs.register_task_definition(
        family=family,
        containerDefinitions=[{"name": "app", "image": "public.ecr.aws/docker/library/busybox:1.36",
                                "memory": 128, "essential": True, "command": ["sleep", "5"]}],
        tags=[{"key": "sim2real", "value": CHECK}],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, td_arn))

    svc_name = ctx.unique_name("sim2real-ecs-lsd-svc-")
    svc = ecs.create_service(
        cluster=cluster_name, serviceName=svc_name, taskDefinition=td_arn,
        desiredCount=0, launchType="EC2",
        tags=[{"key": "sim2real", "value": CHECK}],
    )["service"]
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=cluster_name, service=svc_name, force=True))

    deployments: list[dict[str, Any]] = []
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        deployments = ecs.list_service_deployments(cluster=cluster_name, service=svc_name).get(
            "serviceDeployments", []
        )
        if deployments:
            break
        time.sleep(2)
    assert deployments, "expected at least one service deployment right after CreateService"

    dep = deployments[0]
    assert dep["serviceArn"] == svc["serviceArn"], dep
    assert dep["clusterArn"] == cluster_arn, dep
    assert dep["status"] in _FIRST_DEPLOYMENT_STATUSES, dep["status"]
    assert dep["serviceDeploymentArn"].startswith("arn:aws:ecs:"), dep["serviceDeploymentArn"]

    code, message = _error(lambda: ecs.list_service_deployments(
        cluster=cluster_name, service="sim2real-nonexistent-service-8x92"
    ))
    assert code == "ServiceNotFoundException", code
    expected_message = 'Service not found.'
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises: an
    emulator accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


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
