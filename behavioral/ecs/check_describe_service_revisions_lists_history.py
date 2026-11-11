"""describe-service-revisions-lists-history."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "describe-service-revisions-lists-history"
GROUP = "ordering"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Each of three UpdateService calls mints a service revision that DescribeServiceRevisions
    resolves to the task definition active at that point; ordering deployments by createdAt
    recovers F:1 -> F:2 -> F:3."""
    ecs = ctx.client("ecs")
    cluster_arn = ecs.create_cluster(
        clusterName=ctx.unique_name("sim2real-ecs-revcl-"),
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_arn))

    family = ctx.unique_name("sim2real-ecs-revtd-")
    task_def_arns = []
    for cpu in (128, 192, 256):
        arn = ecs.register_task_definition(
            family=family,
            requiresCompatibilities=["EC2"],
            networkMode="bridge",
            containerDefinitions=[
                {"name": "app", "image": "public.ecr.aws/amazonlinux/amazonlinux:2023", "cpu": cpu, "memory": 128, "essential": True}
            ],
            tags=[{"key": "sim2real-check", "value": CHECK}],
        )["taskDefinition"]["taskDefinitionArn"]
        task_def_arns.append(arn)
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arns[2]))
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arns[1]))
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arns[0]))

    service_name = ctx.unique_name("sim2real-ecs-revsvc-")
    ecs.create_service(
        cluster=cluster_arn, serviceName=service_name, taskDefinition=task_def_arns[0],
        desiredCount=0, launchType="EC2",
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=cluster_arn, service=service_name, force=True))

    # Each deployment must actually settle into a terminal state, AND that settlement must be
    # observed via a listing that has grown to reflect it, before the next UpdateService fires.
    # ListServiceDeployments is itself eventually consistent: right after UpdateService returns,
    # a poll that only checks "is the latest-by-createdAt entry terminal" can spuriously succeed
    # by observing the *previous* (already-terminal) deployment before the new one has even been
    # indexed -- which is exactly why the naive version under-counts distinct deployments by the
    # time the final assertion runs. Require the listing to have grown to the expected count
    # (not just "some" terminal entry) before considering a given update settled.
    deployments = _wait_for_deployment_count(ecs, cluster_arn, service_name, expected_count=1)
    for idx, arn in enumerate(task_def_arns[1:], start=2):
        ecs.update_service(cluster=cluster_arn, service=service_name, taskDefinition=arn)
        deployments = _wait_for_deployment_count(ecs, cluster_arn, service_name, expected_count=idx)

    assert len(deployments) == 3, f"expected exactly 3 service deployments (1 create + 2 updates), got {len(deployments)}"

    details = ecs.describe_service_deployments(
        serviceDeploymentArns=[d["serviceDeploymentArn"] for d in deployments]
    )["serviceDeployments"]
    details_sorted = sorted(details, key=lambda d: d["createdAt"])
    revision_arns_in_order = [d["targetServiceRevision"]["arn"] for d in details_sorted]
    assert len(set(revision_arns_in_order)) == 3, "expected 3 distinct service revisions"

    revisions = ecs.describe_service_revisions(serviceRevisionArns=revision_arns_in_order)["serviceRevisions"]
    by_arn = {r["serviceRevisionArn"]: r["taskDefinition"] for r in revisions}
    task_def_sequence = [by_arn[arn] for arn in revision_arns_in_order]

    assert task_def_sequence == task_def_arns, (
        f"chronological revision->taskDefinition sequence {task_def_sequence} != expected {task_def_arns}"
    )


# ===== helpers =====
_TERMINAL_DEPLOYMENT_STATUSES = {
    "SUCCESSFUL", "STOPPED", "ROLLBACK_SUCCESSFUL", "ROLLBACK_FAILED",
}


def _wait_for_deployment_count(ecs, cluster_arn: str, service_name: str, expected_count: int, timeout_s: float = 120.0):
    """Poll ListServiceDeployments until it has grown to at least `expected_count` entries AND
    the most-recently-created one has reached a terminal status -- both conditions are needed
    because the listing itself is eventually consistent, so "latest entry is terminal" alone can
    be satisfied by a stale read that hasn't yet indexed the newest deployment."""

    def _snapshot():
        return ecs.list_service_deployments(cluster=cluster_arn, service=service_name)["serviceDeployments"]

    def _ready(deps):
        if len(deps) < expected_count:
            return False
        latest = sorted(deps, key=lambda d: d["createdAt"])[-1]
        return latest["status"] in _TERMINAL_DEPLOYMENT_STATUSES

    return _poll_until(_snapshot, _ready, timeout_s=timeout_s, interval_s=3.0)


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
