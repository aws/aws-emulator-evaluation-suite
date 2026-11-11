"""concurrent-update-service-primary-task-set-race."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-update-service-primary-task-set-race"
GROUP = "concurrency"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent UpdateServicePrimaryTaskSet calls resolve to exactly one consistent
    PRIMARY task set without corrupting task-set state, even when many racers flip
    the primary back and forth in parallel."""
    ecs = ctx.client("ecs")

    cluster_name = ctx.unique_name("sim2real-behav-cl-")
    cluster_arn = ecs.create_cluster(
        clusterName=cluster_name, tags=[{"key": "sim2real", "value": "true"}]
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _safe_delete_cluster(ctx, cluster_arn))

    family = ctx.unique_name("sim2real-behav-td-")
    task_def_arn = ecs.register_task_definition(
        family=family,
        containerDefinitions=[
            {"name": "c", "image": "public.ecr.aws/docker/library/alpine:3.19", "memory": 64, "essential": True}
        ],
        tags=[{"key": "sim2real", "value": "true"}],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))

    service_name = ctx.unique_name("sim2real-behav-svc-")
    service_arn = ecs.create_service(
        cluster=cluster_arn,
        serviceName=service_name,
        desiredCount=0,
        deploymentController={"type": "EXTERNAL"},
        tags=[{"key": "sim2real", "value": "true"}],
    )["service"]["serviceArn"]
    ctx.on_cleanup(lambda: _safe_delete_service(ctx, cluster_arn, service_arn))

    set_a = ecs.create_task_set(
        cluster=cluster_arn,
        service=service_arn,
        taskDefinition=task_def_arn,
        launchType="EXTERNAL",
        tags=[{"key": "sim2real", "value": "true"}],
    )["taskSet"]
    set_b = ecs.create_task_set(
        cluster=cluster_arn,
        service=service_arn,
        taskDefinition=task_def_arn,
        launchType="EXTERNAL",
        tags=[{"key": "sim2real", "value": "true"}],
    )["taskSet"]
    id_a, id_b = set_a["id"], set_b["id"]

    # Establish a known baseline: A is primary.
    ecs.update_service_primary_task_set(cluster=cluster_arn, service=service_arn, primaryTaskSet=id_a)

    # Race: many threads alternately flip primary between A and B.
    def _flip(target_id: str) -> str | None:
        try:
            ecs.update_service_primary_task_set(
                cluster=cluster_arn, service=service_arn, primaryTaskSet=target_id
            )
            return None
        except Exception as exc:  # noqa: BLE001 - capture ClientError code
            return _error_code_from_exc(exc)

    targets = [id_a if i % 2 == 0 else id_b for i in range(12)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        errors = list(pool.map(_flip, targets))

    unexpected = [e for e in errors if e is not None]
    assert not unexpected, f"unexpected errors during concurrent primary flips: {unexpected}"

    # Poll until the task sets settle, then verify exactly one PRIMARY.
    def _describe() -> dict[str, Any]:
        resp = ecs.describe_task_sets(cluster=cluster_arn, service=service_arn, taskSets=[id_a, id_b])
        return {ts["id"]: ts["status"] for ts in resp["taskSets"]}

    statuses = _poll_until(
        lambda: _describe(),
        lambda d: sorted(d.values()) in (["ACTIVE", "PRIMARY"],),
        timeout_s=30.0,
        interval_s=1.0,
    )
    primaries = [k for k, v in statuses.items() if v == "PRIMARY"]
    actives = [k for k, v in statuses.items() if v == "ACTIVE"]
    assert len(primaries) == 1, f"expected exactly one PRIMARY task set, got statuses={statuses}"
    assert len(actives) == 1, f"expected exactly one ACTIVE task set, got statuses={statuses}"
    assert set(primaries + actives) == {id_a, id_b}, f"task-set identities corrupted: {statuses}"


def _error_code_from_exc(exc: Exception) -> str:
    resp = getattr(exc, "response", None)
    if isinstance(resp, dict):
        return resp.get("Error", {}).get("Code", type(exc).__name__)
    return type(exc).__name__


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last}")


def _safe_delete_service(ctx, cluster_arn: str, service_arn: str) -> None:
    ecs = ctx.client("ecs")
    try:
        # DescribeTaskSets rejects an empty taskSets list; the service lists its task sets.
        services = ecs.describe_services(cluster=cluster_arn, services=[service_arn])["services"]
        for ts in (services[0].get("taskSets", []) if services else []):
            ecs.delete_task_set(cluster=cluster_arn, service=service_arn, taskSet=ts["id"], force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ClusterNotFoundException",
            "ServiceNotFoundException",
            "TaskSetNotFoundException",
        ):
            raise
    try:
        ecs.delete_service(cluster=cluster_arn, service=service_arn, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ClusterNotFoundException",
            "ServiceNotFoundException",
        ):
            raise


def _safe_delete_cluster(ctx, cluster_arn: str) -> None:
    """Delete the cluster, retrying every 2 s while its services or tasks drain; a cluster already
    gone is fine and any other failure raises."""
    ecs = ctx.client("ecs")
    deadline = time.monotonic() + 60.0
    while True:
        try:
            ecs.delete_cluster(cluster=cluster_arn)
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
