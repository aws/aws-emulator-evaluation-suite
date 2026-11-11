"""op-contract-start-task."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-start-task"
GROUP = "error-semantics"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartTask on a real cluster with an unregistered container instance returns 200 with no
    task and one failure naming that instance, starting nothing, while on a missing cluster it is
    refused ClusterNotFoundException 'Cluster not found.'."""
    ecs = ctx.client("ecs")
    sts = ctx.client("sts")

    cluster_name = ctx.unique_name("sim2real-ecs-stask-")
    ecs.create_cluster(clusterName=cluster_name)
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_name))

    family = ctx.unique_name("sim2real-ecs-stask-td-")
    td_arn = ecs.register_task_definition(
        family=family,
        containerDefinitions=[{"name": "app", "image": "public.ecr.aws/docker/library/busybox:1.36",
                                "memory": 128, "essential": True, "command": ["sleep", "5"]}],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, td_arn))

    # The container-instance ARN's account id must match the caller's account, otherwise ECS
    # rejects the whole request up front with InvalidParameterException("AccountIDs mismatch")
    # rather than exercising the per-item "not registered" failure path being tested here.
    account_id = sts.get_caller_identity()["Account"]
    bogus_container_instance = (
        f"arn:aws:ecs:{ctx.region}:{account_id}:container-instance/{cluster_name}/"
        "0000000000000000000000000000abcd"
    )
    resp = ecs.start_task(
        cluster=cluster_name,
        containerInstances=[bogus_container_instance],
        taskDefinition=td_arn,
    )
    # ECS normalizes the ARN in the failure entry to whatever container-instance ARN format
    # the account has opted into (long-form with cluster name embedded, or the older short-form
    # without it), regardless of which form was supplied in the request. Accept either.
    bogus_container_instance_short = (
        f"arn:aws:ecs:{ctx.region}:{account_id}:container-instance/"
        "0000000000000000000000000000abcd"
    )
    assert resp.get("tasks", []) == [], resp.get("tasks")
    failures = resp.get("failures", [])
    assert len(failures) == 1, failures
    assert failures[0]["arn"] in (bogus_container_instance, bogus_container_instance_short), failures[0]
    assert failures[0].get("reason"), failures[0]

    # Independent read at the destination: the response's own tasks=[] could be
    # trusted blindly by a target that fabricates the field, so confirm via a
    # different operation that nothing was actually placed in the cluster.
    listed_tasks = ecs.list_tasks(cluster=cluster_name).get("taskArns", [])
    assert listed_tasks == [], listed_tasks

    # The container-instance ARN must reference the same (nonexistent) cluster named in the
    # request, otherwise ECS rejects the request up front with InvalidParameterException for
    # the ARN/cluster mismatch before it ever gets to checking whether the cluster exists.
    nonexistent_cluster = "sim2real-nonexistent-cluster-5510"
    bogus_container_instance_for_missing_cluster = (
        f"arn:aws:ecs:{ctx.region}:{account_id}:container-instance/{nonexistent_cluster}/"
        "0000000000000000000000000000abcd"
    )
    code, message = _error(lambda: ecs.start_task(
        cluster=nonexistent_cluster,
        containerInstances=[bogus_container_instance_for_missing_cluster],
        taskDefinition=td_arn,
    ))
    assert code == "ClusterNotFoundException", code
    assert message == "Cluster not found.", message


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected success
    raises, because an emulator accepting input real AWS refuses must fail loudly rather than
    read as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
