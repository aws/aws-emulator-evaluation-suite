"""delete-cluster-with-active-services-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-cluster-with-active-services-rejected"
GROUP = "overly-permissive"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCluster is refused while an active service still exists in it, and succeeds once it's gone."""
    ecs = ctx.client("ecs")
    cluster_name = ctx.unique_name("sim2real-dc-cluster-")
    ecs.create_cluster(clusterName=cluster_name, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _safe_delete_cluster(ecs, cluster_name))

    taskdef_arn = ecs.register_task_definition(
        family=ctx.unique_name("sim2real-dc-taskdef-"),
        networkMode="bridge",
        requiresCompatibilities=["EC2"],
        containerDefinitions=[
            {"name": "app", "image": "public.ecr.aws/docker/library/busybox:1.36", "cpu": 64, "memory": 64, "essential": True, "command": ["sleep", "60"]}
        ],
        tags=[{"key": "sim2real", "value": CHECK}],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, taskdef_arn))

    service_name = ctx.unique_name("sim2real-dc-svc-")
    ecs.create_service(
        cluster=cluster_name,
        serviceName=service_name,
        taskDefinition=taskdef_arn,
        desiredCount=0,
        launchType="EC2",
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_service(ecs, cluster_name, service_name))

    code, message = _error(lambda: ecs.delete_cluster(cluster=cluster_name))
    assert code == "ClusterContainsServicesException", f"expected ClusterContainsServicesException, got {code}"
    assert message == 'The Cluster cannot be deleted while Services are active.', f"expected the exact active-services message, got {message!r}"

    still_there = ecs.describe_clusters(clusters=[cluster_name])["clusters"]
    assert any(c["clusterName"] == cluster_name and c["status"] == "ACTIVE" for c in still_there), (
        "cluster was mutated/removed despite the rejected DeleteCluster call"
    )

    # positive control: once the blocking service is gone, deletion succeeds.
    ecs.delete_service(cluster=cluster_name, service=service_name, force=True)
    _poll_service_gone(ecs, cluster_name, service_name)
    ecs.delete_cluster(cluster=cluster_name)
    remaining = ecs.describe_clusters(clusters=[cluster_name])["clusters"]
    assert not any(c["clusterName"] == cluster_name and c["status"] == "ACTIVE" for c in remaining), (
        "cluster still ACTIVE after the blocking service was removed and DeleteCluster retried"
    )


# ===== helpers =====

def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_service_gone(ecs, cluster_name, service_name, timeout_s=60.0, interval_s=3.0):
    import time

    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        described = ecs.describe_services(cluster=cluster_name, services=[service_name])["services"]
        if not described or described[0]["status"] == "INACTIVE":
            return
        last_status = described[0]["status"]
        time.sleep(interval_s)
    raise AssertionError(
        f"service {service_name} did not reach INACTIVE within {timeout_s}s of delete_service; last status {last_status}"
    )


def _safe_delete_service(ecs, cluster_name, service_name):
    try:
        ecs.delete_service(cluster=cluster_name, service=service_name, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ClusterNotFoundException",
            "ServiceNotFoundException",
        ):
            raise


def _safe_delete_cluster(ecs, cluster_name):
    try:
        ecs.delete_cluster(cluster=cluster_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ClusterNotFoundException":
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
