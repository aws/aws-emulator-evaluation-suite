"""list-tasks-nonexistent-service-filter-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-tasks-nonexistent-service-filter-rejected"
GROUP = "error-semantics"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListTasks filtered by a serviceName the cluster does not have is refused
    ServiceNotFoundException 'Service not found.', while the same filter on a real service
    returns an empty taskArns list."""
    ecs = ctx.client("ecs")
    cluster_arn = _create_cluster(ctx)
    bogus_service = ctx.unique_name("sim2real-behav-nosuchsvc-")

    code, message = _error(lambda: ecs.list_tasks(cluster=cluster_arn, serviceName=bogus_service))
    assert code == "ServiceNotFoundException", f"expected ServiceNotFoundException, got {code}"
    assert message == "Service not found.", f"unexpected message: {message!r}"

    # positive control: a real, existing service in the SAME cluster must NOT raise.
    service_name = _create_service(ctx, cluster_arn)
    ok = ecs.list_tasks(cluster=cluster_arn, serviceName=service_name)
    assert ok["taskArns"] == [], (
        f"expected no tasks for a freshly created desiredCount=0 service, got {ok['taskArns']}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"].get("Code"), e.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")

def _create_cluster(ctx):
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-behav-cluster-")
    arn = ecs.create_cluster(
        clusterName=name, tags=[{"key": "sim2real-check", "value": CHECK}]
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _safe_delete_cluster(ecs, arn))
    return arn


def _create_service(ctx, cluster_arn: str) -> str:
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-behav-td-")
    td_arn = ecs.register_task_definition(
        family=family,
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "memory": 128,
                "essential": True,
                "command": ["sleep", "5"],
            }
        ],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, td_arn))

    service_name = ctx.unique_name("sim2real-behav-svc-")
    ecs.create_service(
        cluster=cluster_arn,
        serviceName=service_name,
        taskDefinition=td_arn,
        desiredCount=0,
        launchType="EC2",
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )
    ctx.on_cleanup(
        lambda: _safe(lambda: ecs.delete_service(cluster=cluster_arn, service=service_name, force=True))
    )
    return service_name


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ClusterNotFoundException",
            "ServiceNotFoundException",
        ):
            raise


#: The ecs suite's cleanup budget; DeleteCluster is retried within it while tasks or services drain.
_CLEANUP_S = 900.0
_DRAINING = ("ClusterContainsTasksException", "ClusterContainsServicesException")


def _safe_delete_cluster(ecs, arn: str) -> None:
    """Delete the cluster, retrying every 2 s while stopped tasks or deleted services still drain;
    an already-gone cluster is done, anything else (or a drain past the budget) raises."""
    deadline = time.monotonic() + _CLEANUP_S
    while True:
        try:
            ecs.delete_cluster(cluster=arn)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ClusterNotFoundException":
                return
            if code not in _DRAINING or time.monotonic() >= deadline:
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
