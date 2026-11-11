"""run-task-nonexistent-cluster-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

DEFAULT_CONTAINER_DEFS = [
    {
        "name": "app",
        "image": "amazonlinux:2",
        "cpu": 10,
        "memory": 64,
        "essential": True,
    }
]

CHECK = "run-task-nonexistent-cluster-fails"
GROUP = 'overly-permissive'
SERVICES = ['ecs']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """RunTask against a nonexistent cluster must fail (overly-permissive
    check)."""
    ecs = ctx.client("ecs")
    td = ecs.register_task_definition(
        family=ctx.unique_name("sim2real-behav-ecs-taskdef-"),
        containerDefinitions=DEFAULT_CONTAINER_DEFS,
        tags=[{"key": "sim2real", "value": "true"}],
    )["taskDefinition"]
    ctx.on_cleanup(lambda a=td["taskDefinitionArn"]: ecs.delete_task_definitions(taskDefinitions=[a]))
    ctx.on_cleanup(lambda a=td["taskDefinitionArn"]: ecs.deregister_task_definition(taskDefinition=a))
    bogus_cluster = ctx.unique_name("sim2real-behav-ecs-cluster-missing-")
    try:
        resp = ecs.run_task(
            cluster=bogus_cluster, taskDefinition=td["taskDefinitionArn"]
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    else:
        raise AssertionError(f"RunTask against a missing cluster SUCCEEDED and returned {resp!r}")
    assert code == "ClusterNotFoundException", f"expected ClusterNotFoundException, got {code}"
    assert message == "Cluster not found.", f"refusal message {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
