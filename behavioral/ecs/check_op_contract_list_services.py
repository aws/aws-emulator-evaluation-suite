"""op-contract-list-services."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-list-services"
GROUP = "error-semantics"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListServices scopes results to the given cluster and excludes services in other
    clusters; ClusterNotFoundException for a cluster that doesn't exist."""
    ecs = ctx.client("ecs")

    cluster_a = ctx.unique_name("sim2real-ecs-lsvc-a-")
    cluster_b = ctx.unique_name("sim2real-ecs-lsvc-b-")
    ecs.create_cluster(clusterName=cluster_a, tags=[{"key": "sim2real", "value": "true"}])
    ecs.create_cluster(clusterName=cluster_b, tags=[{"key": "sim2real", "value": "true"}])
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_a))
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_b))

    family = ctx.unique_name("sim2real-ecs-lsvc-td-")
    td_arn = ecs.register_task_definition(
        family=family,
        containerDefinitions=[{"name": "app", "image": "public.ecr.aws/docker/library/busybox:1.36",
                                "memory": 128, "essential": True, "command": ["sleep", "5"]}],
        tags=[{"key": "sim2real", "value": "true"}],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, td_arn))

    svc_name = ctx.unique_name("sim2real-ecs-lsvc-svc-")
    svc_arn = ecs.create_service(
        cluster=cluster_a, serviceName=svc_name, taskDefinition=td_arn,
        desiredCount=0, launchType="EC2",
        tags=[{"key": "sim2real", "value": "true"}],
    )["service"]["serviceArn"]
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=cluster_a, service=svc_name, force=True))

    arns_a = ecs.list_services(cluster=cluster_a)["serviceArns"]
    arns_b = ecs.list_services(cluster=cluster_b)["serviceArns"]
    assert svc_arn in arns_a, arns_a
    assert svc_arn not in arns_b, arns_b
    assert arns_b == [], arns_b

    code, message = _error(lambda: ecs.list_services(cluster="sim2real-nonexistent-cluster-4471"))
    assert code == "ClusterNotFoundException", code
    expected_message = 'Cluster not found.'
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
