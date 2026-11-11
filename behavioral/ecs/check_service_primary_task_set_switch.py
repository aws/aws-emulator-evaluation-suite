"""service-primary-task-set-switch."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "service-primary-task-set-switch"
GROUP = "concurrency"
SERVICES = ["ecs"]

_TAGS = [{"key": "sim2real", "value": "true"}]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateServicePrimaryTaskSet atomically flips PRIMARY under concurrent contention: exactly one winner."""

    ecs = ctx.client("ecs")
    cluster_name = ctx.unique_name("sim2real-ts-cluster-")
    ecs.create_cluster(clusterName=cluster_name, tags=_TAGS)
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_name))

    # launchType=EXTERNAL keeps this a pure control-plane exercise with no networkConfiguration
    # and no dependence on a default VPC (which a freshly provisioned account may not have).
    family = ctx.unique_name("sim2real-ts-td-")
    td_arn = ecs.register_task_definition(
        family=family,
        containerDefinitions=[{"name": "app", "image": "public.ecr.aws/amazonlinux/amazonlinux:2023-minimal", "essential": True, "memory": 64}],
        tags=_TAGS,
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, td_arn))

    service_name = ctx.unique_name("sim2real-ts-svc-")
    ecs.create_service(
        cluster=cluster_name,
        serviceName=service_name,
        # Real AWS rejects CreateService without desiredCount ("DesiredCount is missing"), even
        # for the EXTERNAL deployment controller where task sets (not the service) drive scale.
        desiredCount=0,
        deploymentController={"type": "EXTERNAL"},
        tags=_TAGS,
    )
    ctx.on_cleanup(lambda: _delete_service_best_effort(ecs, cluster_name, service_name))

    ts_a = ecs.create_task_set(
        cluster=cluster_name,
        service=service_name,
        taskDefinition=td_arn,
        launchType="EXTERNAL",
        tags=_TAGS,
    )["taskSet"]
    ts_b = ecs.create_task_set(
        cluster=cluster_name,
        service=service_name,
        taskDefinition=td_arn,
        launchType="EXTERNAL",
        tags=_TAGS,
    )["taskSet"]
    id_a, id_b = ts_a["id"], ts_b["id"]

    def _flip(target_id):
        try:
            ecs.update_service_primary_task_set(cluster=cluster_name, service=service_name, primaryTaskSet=target_id)
            return None
        except Exception as err:  # noqa: BLE001 - we want to observe any racer failure, not silence it
            return err

    # Fire alternating "make A primary" / "make B primary" calls concurrently: whichever lands
    # last wins, but the service must never end up with zero or two PRIMARY task sets.
    targets = [id_a if i % 2 == 0 else id_b for i in range(10)]
    with ThreadPoolExecutor(max_workers=5) as pool:
        errors = list(pool.map(_flip, targets))
    assert all(e is None for e in errors), f"unexpected racer failures: {[e for e in errors if e]}"

    def _describe():
        return ecs.describe_task_sets(cluster=cluster_name, service=service_name, taskSets=[id_a, id_b])["taskSets"]

    final = _poll_until(
        _describe,
        lambda ts: sorted(s["status"] for s in ts) == ["ACTIVE", "PRIMARY"],
        timeout_s=30.0,
        interval_s=1.0,
    )
    assert len(final) == 2, f"expected both task sets to still be describable, got {len(final)}: {final}"
    primaries = [s for s in final if s["status"] == "PRIMARY"]
    non_primaries = [s for s in final if s["id"] != primaries[0]["id"]] if primaries else []
    assert len(primaries) == 1, f"expected exactly one PRIMARY task set under contention, got {len(primaries)}: {final}"
    assert primaries[0]["id"] in (id_a, id_b), f"PRIMARY id {primaries[0]['id']} is neither racer id {id_a!r}/{id_b!r}"
    assert len(non_primaries) == 1 and non_primaries[0]["status"] == "ACTIVE", (
        f"the non-primary task set must be demoted to ACTIVE, never left as a second PRIMARY, got {final}"
    )


def _poll_until(probe, predicate, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last}")


def _delete_service_best_effort(ecs, cluster_name, service_name):
    from botocore.exceptions import ClientError

    try:
        ecs.delete_service(cluster=cluster_name, service=service_name, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ClusterNotFoundException",
            "ServiceNotFoundException",
        ):
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
