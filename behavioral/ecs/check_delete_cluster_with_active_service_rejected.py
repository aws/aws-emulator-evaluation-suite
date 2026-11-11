"""delete-cluster-with-active-service-rejected."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-cluster-with-active-service-rejected"
GROUP = "overly-permissive"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCluster on a cluster that still hosts an ACTIVE service is rejected, cluster
    untouched; once the blocking service is removed the identical DeleteCluster call succeeds."""
    ecs = ctx.client("ecs")

    cluster_arn = ecs.create_cluster(
        clusterName=ctx.unique_name("sim2real-ecs-cl-"), tags=[{"key": "sim2real", "value": CHECK}]
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster_retrying(ecs, cluster_arn))

    family = ctx.unique_name("sim2real-ecs-td-")
    task_def_arn = ecs.register_task_definition(
        family=family,
        containerDefinitions=[
            {"name": "c", "image": "busybox:1.36", "cpu": 64, "memory": 64, "essential": True}
        ],
        tags=[{"key": "sim2real", "value": CHECK}],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))

    service_arn = ecs.create_service(
        cluster=cluster_arn,
        serviceName=ctx.unique_name("sim2real-ecs-svc-"),
        desiredCount=0,
        launchType="EC2",
        taskDefinition=task_def_arn,
        tags=[{"key": "sim2real", "value": CHECK}],
    )["service"]["serviceArn"]
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=cluster_arn, service=service_arn, force=True))

    code, message = _error(lambda: ecs.delete_cluster(cluster=cluster_arn))
    assert code == "ClusterContainsServicesException", (
        f"expected ClusterContainsServicesException deleting a cluster with an ACTIVE service, got {code}"
    )
    assert message == 'The Cluster cannot be deleted while Services are active.', f"expected the exact active-services message, got {message!r}"

    desc = ecs.describe_clusters(clusters=[cluster_arn])["clusters"][0]
    assert desc["status"] == "ACTIVE", f"cluster should be untouched by the rejected delete: {desc}"

    # positive control: once the blocking service is gone, the identical DeleteCluster call succeeds.
    ecs.delete_service(cluster=cluster_arn, service=service_arn, force=True)

    def _service_status() -> str:
        described = ecs.describe_services(cluster=cluster_arn, services=[service_arn])["services"]
        return described[0]["status"] if described else "GONE"

    _poll_until(
        _service_status,
        lambda status: status in ("INACTIVE", "GONE"),
        timeout_s=90.0,
        interval_s=3.0,
        description="blocking service reaching INACTIVE",
    )

    ecs.delete_cluster(cluster=cluster_arn)

    def _cluster_status() -> str:
        clusters = ecs.describe_clusters(clusters=[cluster_arn])["clusters"]
        return clusters[0]["status"] if clusters else "GONE"

    final_status = _poll_until(
        _cluster_status,
        lambda status: status in ("INACTIVE", "GONE"),
        timeout_s=60.0,
        interval_s=3.0,
        description="cluster reaching INACTIVE after the blocker was removed",
    )
    assert final_status in ("INACTIVE", "GONE"), (
        f"the identical DeleteCluster call should succeed once the blocking service is gone, got {final_status}"
    )


# ===== helpers =====

def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float,
    interval_s: float,
    description: str,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _delete_cluster_retrying(ecs: Any, cluster_arn: str) -> None:
    deadline = time.monotonic() + 60.0
    retryable = {
        "ClusterContainsTasksException",
        "ClusterContainsServicesException",
        "ClusterContainsContainerInstancesException",
        "ClusterContainsCapacityProviderException",
        "UpdateInProgressException",
    }
    while True:
        try:
            ecs.delete_cluster(cluster=cluster_arn)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ClusterNotFoundException":
                return
            if code in retryable and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise


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
