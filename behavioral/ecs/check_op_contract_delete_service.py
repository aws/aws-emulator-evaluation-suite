"""op-contract-deleteService."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-deleteService"
GROUP = "error-semantics"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteService rejects a running service without force=True, then succeeds with it."""
    ecs = ctx.client("ecs")

    cluster_name = ctx.unique_name("sim2real-behav-cluster-")
    ecs.create_cluster(clusterName=cluster_name, tags=[{"key": "sim2real-check", "value": CHECK}])
    ctx.on_cleanup(lambda: _try_delete_cluster(ecs, cluster_name))

    family = ctx.unique_name("sim2real-behav-td-")
    td_arn = ecs.register_task_definition(
        family=family,
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "cpu": 128,
                "memory": 128,
                "essential": True,
            }
        ],
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, td_arn))

    service_name = ctx.unique_name("sim2real-behav-svc-")
    ecs.create_service(
        cluster=cluster_name,
        serviceName=service_name,
        taskDefinition=family,
        desiredCount=1,
        launchType="EC2",
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )

    err, message = _error(lambda: ecs.delete_service(cluster=cluster_name, service=service_name))
    assert err == "InvalidParameterException", f"expected InvalidParameterException (force required), got {err}"
    expected_message = 'The service cannot be stopped while it is scaled above 0.'
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    still = ecs.describe_services(cluster=cluster_name, services=[service_name])["services"][0]
    assert still["status"] == "ACTIVE", f"expected ACTIVE after rejected delete, got {still['status']}"
    assert still["desiredCount"] == 1, f"expected desiredCount unchanged at 1, got {still['desiredCount']}"

    resp = ecs.delete_service(cluster=cluster_name, service=service_name, force=True)
    assert resp["service"]["serviceName"] == service_name, (
        f"forced delete response named {resp['service']['serviceName']!r}, expected {service_name!r}"
    )
    assert resp["service"]["status"] == "DRAINING", f"expected DRAINING immediately after forced delete, got {resp['service']['status']}"

    deadline = time.monotonic() + 90
    final_status = None
    while time.monotonic() < deadline:
        described = ecs.describe_services(cluster=cluster_name, services=[service_name])["services"]
        final_status = described[0]["status"] if described else None
        if final_status == "INACTIVE":
            break
        time.sleep(3)
    assert final_status == "INACTIVE", f"service never reached INACTIVE, last={final_status}"


# ===== helpers =====
def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises: an
    emulator accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _try_delete_cluster(ecs, cluster_name, timeout_s=60.0):
    """Delete the cluster, retrying while its services and tasks are still draining; a cluster
    that is already gone is done, any other error raises."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ecs.delete_cluster(cluster=cluster_name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ClusterNotFoundException":
                return
            if code not in (
                "ClusterContainsServicesException",
                "ClusterContainsTasksException",
                "UpdateInProgressException",
            ) or time.monotonic() >= deadline:
                raise
            time.sleep(2)


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
